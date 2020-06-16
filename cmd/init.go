package cmd

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	config "github.com/alexellis/k3sup/pkg/config"
	operator "github.com/alexellis/k3sup/pkg/operator"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

var defaultDockerCmds = []string{`sudo yum remove docker \
		docker-client \
		docker-client-latest \
		docker-common \
		docker-latest \
		docker-latest-logrotate \
		docker-logrotate \
		docker-engine`,
	"sudo yum install -y yum-utils",
	"sudo yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo",
	"sudo yum install docker-ce docker-ce-cli containerd.io -y",
	"sudo systemctl daemon-reload", "systemctl start docker", "systemctl daemon-reload",
}

// MakeInit init docker and copy、curl k3s cli or k3s image
func MakeInit() *cobra.Command {
	var command = &cobra.Command{
		Use:          "init",
		Short:        "init",
		Example:      `  k3sup before todo`,
		SilenceUsage: false,
	}
	command.Run = func(cmd *cobra.Command, args []string) {

	}
	command.AddCommand(makeShell(), scpK3sClitAndLoadImageTar(), downloadK3sClitAndLoadImageTar())
	return command
}

func makeShell() *cobra.Command {
	var command = &cobra.Command{
		Use:          "shell",
		Short:        "init shell",
		Example:      `k3sup init shell --ip 192.168.100.135 --user root`,
		SilenceUsage: false,
	}
	flags(command)
	command.Flags().StringArray("command", []string{"curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun"}, "install docker")
	command.Run = func(command *cobra.Command, _ []string) {
		user, _ := command.Flags().GetString("user")
		port, _ := command.Flags().GetInt("ssh-port")
		ip, _ := command.Flags().GetIP("ip")
		fmt.Println("Public IP: " + ip.String())

		sshKey, _ := command.Flags().GetString("ssh-key")
		sshKeyPath := expandPath(sshKey)
		fmt.Printf("ssh -i %s -p %d %s@%s\n", sshKeyPath, port, user, ip.String())

		authMethod, closeSSHAgent, err := loadPublickey(sshKeyPath)
		if err != nil {
			fmt.Println(errors.Wrapf(err, "unable to load the ssh key with path %q", sshKeyPath).Error())
			return
		}
		defer closeSSHAgent()

		config := &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{authMethod},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		address := fmt.Sprintf("%s:%d", ip.String(), port)
		operator, err := operator.NewSSHOperator(address, config)
		if err != nil {
			fmt.Printf("ssh connect faield %s", err.Error())
			return
		}
		defer operator.Close()

		dockerCmds, _ := command.Flags().GetStringArray("command")
		if len(dockerCmds) == 0 {
			dockerCmds = append(dockerCmds, defaultDockerCmds...)
		}

		for _, v := range dockerCmds {
			res, err := operator.Execute(v)
			if err != nil {
				fmt.Printf("install docker failed %s", err.Error())
				return
			}

			if len(res.StdErr) > 0 {
				fmt.Printf("stderr: %q", res.StdErr)
			}
			if len(res.StdOut) > 0 {
				fmt.Printf("stdout: %q", res.StdOut)
			}
		}

	}
	return command
}

func scpK3sClitAndLoadImageTar() *cobra.Command {
	var command = &cobra.Command{
		Use:          "scp",
		Short:        "copy k3s cli,k3s image",
		Example:      `k3sup  init k3s --ip 192.168.100.135 --user root --k3s v1.16.3-k3s2 --k3s-image-tar k3s-airgap-images-amd64.tar`,
		SilenceUsage: false,
	}
	flags(command)
	command.Flags().String("k3s", "k3s", "k3s cli file path")
	command.Flags().String("k3s-image-tar", "k3s", "k3s image tar file path")
	command.Run = func(command *cobra.Command, _ []string) {
		k3sCliPath, _ := command.Flags().GetString("k3s")
		k3sImageTar, _ := command.Flags().GetString("k3s-image-tar")
		user, _ := command.Flags().GetString("user")
		ip, _ := command.Flags().GetIP("ip")

		dst := fmt.Sprintf("%s@%s:/tmp/\n", user, ip.String())
		var g errgroup.Group

		var cpfiles = [...]string{k3sImageTar, k3sCliPath}
		for _, v := range cpfiles {
			if v == "" {
				continue
			}
			g.Go(func() error {
				execCmd := exec.Command("scp", "-r", v, dst)
				execCmd.Stderr = os.Stderr
				execCmd.Stdout = os.Stdout
				execCmd.Stdin = os.Stdin
				if err := execCmd.Run(); err != nil {
					return errors.Wrapf(err, "exec cmd [%s]", execCmd.String())
				}
				return nil
			})
		}

		if err := g.Wait(); err != nil {
			fmt.Printf("copy k3s cli and k3s image failed. %s\n", err.Error())
			return
		}
		port, _ := command.Flags().GetInt("ssh-port")

		fmt.Println("Public IP: " + ip.String())

		sshKey, _ := command.Flags().GetString("ssh-key")

		sshKeyPath := expandPath(sshKey)
		fmt.Printf("ssh -i %s -p %d %s@%s\n", sshKeyPath, port, user, ip.String())

		authMethod, closeSSHAgent, err := loadPublickey(sshKeyPath)
		if err != nil {
			fmt.Printf("unable to load the ssh key with path %q %s", sshKeyPath, err.Error())
			return
		}
		defer closeSSHAgent()

		config := &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{authMethod},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		address := fmt.Sprintf("%s:%d", ip.String(), port)
		operator, err := operator.NewSSHOperator(address, config)
		if err != nil {
			fmt.Printf("ssh connect faield %s", err.Error())
			return
		}
		defer operator.Close()
		cmd := fmt.Sprintf("cd /tmp;mv %s /usr/local/bin/k3s;chmod +x /usr/local/bin/k3s; sudo docker load -i %s;rm -rf %s", filepath.Base(k3sCliPath), filepath.Base(k3sImageTar), filepath.Base(k3sImageTar))
		res, err := operator.Execute(cmd)
		if err != nil {
			fmt.Printf("exec cmd[%s] failed err:%s", cmd, err.Error())
			return
		}
		if len(res.StdErr) > 0 {
			fmt.Printf("stderr: %q", res.StdErr)
		}
		if len(res.StdOut) > 0 {
			fmt.Printf("stdout: %q", res.StdOut)
		}

	}
	return command
}

func downloadK3sClitAndLoadImageTar() *cobra.Command {
	var command = &cobra.Command{
		Use:          "download",
		Short:        "download k3s cli,k3s image,note:确认k3s版本一致",
		Example:      `  k3sup  init download --ip 192.168.100.135 --user root --k3s-cli http://192.168.100.135:888/k3s --k3s-images http://192.168.100.135:888/k3s-airgap-images-amd64.tar`,
		SilenceUsage: false,
	}
	flags(command)
	command.Flags().String("k3s-cli", "", "download k3s cli url")
	command.Flags().String("k3s-images", "", "download k3s images url")
	command.Run = func(command *cobra.Command, _ []string) {

		user, _ := command.Flags().GetString("user")
		ip, _ := command.Flags().GetIP("ip")
		port, _ := command.Flags().GetInt("ssh-port")
		fmt.Println("Public IP: " + ip.String())

		sshKey, _ := command.Flags().GetString("ssh-key")

		sshKeyPath := expandPath(sshKey)
		fmt.Printf("ssh -i %s -p %d %s@%s\n", sshKeyPath, port, user, ip.String())

		authMethod, closeSSHAgent, err := loadPublickey(sshKeyPath)
		if err != nil {
			fmt.Printf("unable to load the ssh key with path %q %s", sshKeyPath, err.Error())
			return
		}
		defer closeSSHAgent()
		config := &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{authMethod},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		address := fmt.Sprintf("%s:%d", ip.String(), port)
		operator, err := operator.NewSSHOperator(address, config)
		if err != nil {
			fmt.Printf("ssh connect faield %s", err.Error())
			return
		}

		downloadK3sCliURL, _ := command.Flags().GetString("k3s-cli")
		downloadK3sImageURL, _ := command.Flags().GetString("k3s-images")
		var cmds []Cmd
		if downloadK3sCliURL != "" {
			cmds = append(cmds, new(k3sCli).BuildCmds(downloadK3sCliURL))
		}
		if downloadK3sImageURL != "" {
			cmds = append(cmds, new(k3sImages).BuildCmds(downloadK3sImageURL))
		}
		defer operator.Close()
		var g errgroup.Group
		for _, cmd := range cmds {
			cmdStr := cmd.String()
			g.Go(func() error {
				fmt.Printf("ssh: %s\n", cmdStr)
				res, err := operator.Execute(cmdStr)
				if err != nil {
					fmt.Printf("exec cmd[%s] failed err:%s", cmd, err.Error())
					return err
				}
				if len(res.StdErr) > 0 {
					fmt.Printf("stderr: %q", res.StdErr)
				}
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			fmt.Println(err)
		}
	}
	return command
}

func flags(command *cobra.Command) {
	command.Flags().IP("ip", net.ParseIP("127.0.0.1"), "Public IP of node")
	command.Flags().String("user", "root", "Username for SSH login")
	command.Flags().String("ssh-key", "~/.ssh/id_rsa", "The ssh key to use for remote login")
	command.Flags().Int("ssh-port", 22, "The port on which to connect for ssh")
	// command.Flags().Bool("sudo", true, "Use sudo for installation. e.g. set to false when using the root user and no sudo is available.")
	command.Flags().String("k3s-version", config.K3sVersion, "Optional version to install, pinned at a default")
}

// Cmd k3s interface
type Cmd interface {
	BuildCmds(string) Cmd
	fmt.Stringer
}

type k3sCli struct {
	cmd string
}

func (k *k3sCli) BuildCmds(url string) Cmd {
	k.cmd = fmt.Sprintf("curl -sfL %s -o /usr/local/bin/k3s;chmod +x /usr/local/bin/k3s;", url)
	return k
}

func (k *k3sCli) String() string {
	return k.cmd
}

type k3sImages struct {
	cmd string
}

func (k *k3sImages) BuildCmds(url string) Cmd {
	k3sImageTar := "k3s-airgap-images-amd64.tar"
	k.cmd = fmt.Sprintf("curl -sfL %s -o %s; sudo docker load -i %s;rm -rf %s; docker tag rancher/pause:3.1 k8s.gcr.io/pause:3.1", url, k3sImageTar, k3sImageTar, k3sImageTar)
	return k
}

func (k *k3sImages) String() string {
	return k.cmd
}
