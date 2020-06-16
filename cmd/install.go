package cmd

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	config "github.com/alexellis/k3sup/pkg/config"
	operator "github.com/alexellis/k3sup/pkg/operator"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

var kubeconfig []byte

func MakeInstall() *cobra.Command {
	var command = &cobra.Command{
		Use:          "install",
		Short:        "Install k3s on a server via SSH",
		Long:         `Install k3s on a server via SSH.`,
		Example:      `  k3sup install --ip 192.168.0.100 --user root`,
		SilenceUsage: true,
	}

	command.Flags().IP("ip", net.ParseIP("127.0.0.1"), "Public IP of node")
	command.Flags().String("user", "root", "Username for SSH login")

	command.Flags().String("ssh-key", "~/.ssh/id_rsa", "The ssh key to use for remote login")
	command.Flags().Int("ssh-port", 22, "The port on which to connect for ssh")
	command.Flags().Bool("sudo", true, "Use sudo for installation. e.g. set to false when using the root user and no sudo is available.")
	command.Flags().Bool("skip-install", false, "Skip the k3s installer")
	command.Flags().String("local-path", "kubeconfig", "Local path to save the kubeconfig file")
	command.Flags().String("context", "default", "Set the name of the kubeconfig context.")
	command.Flags().String("k3s-extra-args", "", "Optional extra arguments to pass to k3s installer, wrapped in quotes (e.g. --k3s-extra-args '--no-deploy servicelb')")
	command.Flags().Bool("no-extras", false, `Disable "servicelb" and "traefik"`)

	command.Flags().Bool("ipsec", false, "Enforces and/or activates optional extra argument for k3s: flannel-backend option: ipsec")
	command.Flags().Bool("merge", false, `Merge the config with existing kubeconfig if it already exists.
Provide the --local-path flag with --merge if a kubeconfig already exists in some other directory`)
	command.Flags().String("k3s-version", config.K3sVersion, "Optional version to install, pinned at a default")

	command.Flags().Bool("local", false, "Perform a local install without using ssh")
	command.Flags().Bool("cluster", false, "Form a dqlite cluster")
	command.Flags().String("install-k3s-shell", "https://get.k3s.io", "install k3s shell url")
	command.Flags().String("k3s-env", "INSTALL_K3S_SKIP_DOWNLOAD=true", "k3s Environment variables")
	command.RunE = func(command *cobra.Command, args []string) error {

		fmt.Printf("Running: k3sup install\n")

		localKubeconfig, _ := command.Flags().GetString("local-path")

		skipInstall, _ := command.Flags().GetBool("skip-install")

		useSudo, _ := command.Flags().GetBool("sudo")
		sudoPrefix := ""
		if useSudo {
			sudoPrefix = "sudo "
		}

		k3sVersion, _ := command.Flags().GetString("k3s-version")
		k3sExtraArgs, _ := command.Flags().GetString("k3s-extra-args")
		k3sNoExtras, _ := command.Flags().GetBool("no-extras")

		flannelIPSec, _ := command.Flags().GetBool("ipsec")

		local, _ := command.Flags().GetBool("local")

		ip, _ := command.Flags().GetIP("ip")

		cluster, _ := command.Flags().GetBool("cluster")

		clusterStr := ""
		if cluster {
			clusterStr = "--cluster-init"
		}

		if flannelIPSec {
			k3sExtraArgs += ` '--flannel-backend ipsec'`
		}
		if k3sNoExtras {
			k3sExtraArgs += `--no-deploy servicelb --no-deploy traefik`
		}

		installk3sExec := fmt.Sprintf("INSTALL_K3S_EXEC='server %s --tls-san %s %s'", clusterStr, ip, strings.TrimSpace(k3sExtraArgs))
		k3sInstallShell, _ := command.Flags().GetString("install-k3s-shell")
		k3sEnv,_:=command.Flags().GetString("k3s-env")
		installK3scommand := fmt.Sprintf("curl -sLS %s | %s INSTALL_K3S_VERSION='%s' %s sh -\n", k3sInstallShell, installk3sExec, k3sVersion, k3sEnv)
		getConfigcommand := fmt.Sprintf(sudoPrefix + "cat /etc/rancher/k3s/k3s.yaml\n")
		merge, _ := command.Flags().GetBool("merge")
		context, _ := command.Flags().GetString("context")

		if local {
			operator := operator.ExecOperator{}

			fmt.Println("export INSTALL_K3S_SKIP_DOWNLOAD=true")
			_, _ = operator.Execute("export INSTALL_K3S_SKIP_DOWNLOAD=true")

			fmt.Printf("Executing: %s\n", installK3scommand)

			res, err := operator.Execute(installK3scommand)
			if err != nil {
				return err
			}

			if len(res.StdErr) > 0 {
				fmt.Printf("stderr: %q", res.StdErr)
			}
			if len(res.StdOut) > 0 {
				fmt.Printf("stdout: %q", res.StdOut)
			}

			err = obtainKubeconfig(operator, getConfigcommand, ip.String(), context, localKubeconfig, merge)
			if err != nil {
				return err
			}

			return nil
		}

		port, _ := command.Flags().GetInt("ssh-port")

		fmt.Println("Public IP: " + ip.String())

		user, _ := command.Flags().GetString("user")
		sshKey, _ := command.Flags().GetString("ssh-key")

		sshKeyPath := expandPath(sshKey)
		fmt.Printf("ssh -i %s -p %d %s@%s\n", sshKeyPath, port, user, ip.String())

		authMethod, closeSSHAgent, err := loadPublickey(sshKeyPath)
		if err != nil {
			return errors.Wrapf(err, "unable to load the ssh key with path %q", sshKeyPath)
		}

		defer closeSSHAgent()

		config := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				authMethod,
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		address := fmt.Sprintf("%s:%d", ip.String(), port)
		operator, err := operator.NewSSHOperator(address, config)

		if err != nil {
			return errors.Wrapf(err, "unable to connect to %s over ssh", address)
		}

		defer operator.Close()

		if !skipInstall {
			fmt.Println("export INSTALL_K3S_SKIP_DOWNLOAD=true")
			_, _ = operator.Execute("export INSTALL_K3S_SKIP_DOWNLOAD=true")
			fmt.Printf("ssh: %s\n", installK3scommand)
			res, err := operator.Execute(installK3scommand)

			if err != nil {
				return fmt.Errorf("error received processing command: %s", err)
			}

			fmt.Printf("Result: %s %s\n", string(res.StdOut), string(res.StdErr))
		}

		fmt.Printf("ssh: %s\n", getConfigcommand)

		err = obtainKubeconfig(operator, getConfigcommand, ip.String(), context, localKubeconfig, merge)
		if err != nil {
			return err
		}

		return nil
	}

	command.PreRunE = func(command *cobra.Command, args []string) error {
		_, ipErr := command.Flags().GetIP("ip")
		if ipErr != nil {
			return ipErr
		}

		_, sshPortErr := command.Flags().GetInt("ssh-port")
		if sshPortErr != nil {
			return sshPortErr
		}
		return nil
	}
	return command
}

func obtainKubeconfig(operator operator.CommandOperator, getConfigcommand, ip, context, localKubeconfig string, merge bool) error {

	res, err := operator.Execute(getConfigcommand)

	if err != nil {
		return fmt.Errorf("error received processing command: %s", err)
	}

	fmt.Printf("Result: %s %s\n", string(res.StdOut), string(res.StdErr))

	absPath, _ := filepath.Abs(localKubeconfig)

	kubeconfig := rewriteKubeconfig(string(res.StdOut), ip, context)

	if merge {
		// Create a merged kubeconfig
		kubeconfig, err = mergeConfigs(absPath, []byte(kubeconfig))
		if err != nil {
			return err
		}
	}

	// Create a new kubeconfig
	if writeErr := writeConfig(absPath, []byte(kubeconfig), false); writeErr != nil {
		return writeErr
	}
	return nil
}

// Generates config files give the path to file: string and the data: []byte
func writeConfig(path string, data []byte, suppressMessage bool) error {
	absPath, _ := filepath.Abs(path)
	if !suppressMessage {
		fmt.Printf("Saving file to: %s\n", absPath)
		fmt.Printf("\n# Test your cluster with:\nexport KUBECONFIG=%s\nkubectl get node -o wide\n", absPath)
	}
	writeErr := ioutil.WriteFile(absPath, []byte(data), 0600)
	if writeErr != nil {
		return writeErr
	}
	return nil
}

func mergeConfigs(localKubeconfigPath string, k3sconfig []byte) ([]byte, error) {
	// Create a temporary kubeconfig to store the config of the newly create k3s cluster
	file, err := ioutil.TempFile(os.TempDir(), "k3s-temp-*")
	if err != nil {
		return nil, fmt.Errorf("Could not generate a temporary file to store the kuebeconfig: %s", err)
	}
	defer file.Close()

	if writeErr := writeConfig(file.Name(), []byte(k3sconfig), true); writeErr != nil {
		return nil, writeErr
	}

	fmt.Printf("Merging with existing kubeconfig at %s\n", localKubeconfigPath)

	// Append KUBECONFIGS in ENV Vars
	appendKubeConfigENV := fmt.Sprintf("KUBECONFIG=%s:%s", localKubeconfigPath, file.Name())

	// Merge the two kubeconfigs and read the output into 'data'
	cmd := exec.Command("kubectl", "config", "view", "--merge", "--flatten")
	cmd.Env = append(os.Environ(), appendKubeConfigENV)
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Could not merge kubeconfigs: %s", err)
	}

	// Remove the temporarily generated file
	err = os.Remove(file.Name())
	if err != nil {
		return nil, errors.Wrapf(err, "Could not remove temporary kubeconfig file: %s", file.Name())
	}

	return data, nil
}

func expandPath(path string) string {
	res, _ := homedir.Expand(path)
	return res
}

func sshAgent(publicKeyPath string) (ssh.AuthMethod, func() error) {
	if sshAgentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		sshAgent := agent.NewClient(sshAgentConn)

		keys, _ := sshAgent.List()
		if len(keys) == 0 {
			return nil, sshAgentConn.Close
		}

		pubkey, err := ioutil.ReadFile(publicKeyPath)
		if err != nil {
			return nil, sshAgentConn.Close
		}

		authkey, _, _, _, err := ssh.ParseAuthorizedKey(pubkey)
		if err != nil {
			return nil, sshAgentConn.Close
		}
		parsedkey := authkey.Marshal()

		for _, key := range keys {
			if bytes.Equal(key.Blob, parsedkey) {
				return ssh.PublicKeysCallback(sshAgent.Signers), sshAgentConn.Close
			}
		}
	}
	return nil, func() error { return nil }
}

func loadPublickey(path string) (ssh.AuthMethod, func() error, error) {
	noopCloseFunc := func() error { return nil }

	key, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, noopCloseFunc, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		if err.Error() != "ssh: cannot decode encrypted private keys" {
			return nil, noopCloseFunc, fmt.Errorf("unable to parse private key: %s", err.Error())
		}

		agent, close := sshAgent(path + ".pub")
		if agent != nil {
			return agent, close, nil
		}

		defer close()

		fmt.Printf("Enter passphrase for '%s': ", path)
		STDIN := int(os.Stdin.Fd())
		bytePassword, _ := terminal.ReadPassword(STDIN)

		// Ignore any error from reading stdin to retain existing behaviour for unit test in
		// install_test.go

		// if err != nil {
		// 	return nil, noopCloseFunc, fmt.Errorf("reading password from stdin failed: %s", err.Error())
		// }

		fmt.Println()

		signer, err = ssh.ParsePrivateKeyWithPassphrase(key, bytePassword)
		if err != nil {
			return nil, noopCloseFunc, fmt.Errorf("parse private key with passphrase failed: %s", err)
		}
	}

	return ssh.PublicKeys(signer), noopCloseFunc, nil
}

func rewriteKubeconfig(kubeconfig string, ip string, context string) []byte {
	if context == "" {
		context = "default"
	}

	kubeconfigReplacer := strings.NewReplacer(
		"127.0.0.1", ip,
		"localhost", ip,
		"default", context,
	)

	return []byte(kubeconfigReplacer.Replace(kubeconfig))
}
