/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/OmarTariq612/goech"
	"github.com/netd-tud/zgrab2/tools/greasy/ech"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "echme",
	Short: "parse base64 encoded ECH configs",
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {

		reader := bufio.NewScanner(os.Stdin)

		for reader.Scan() {
			input := reader.Text()
			if err := reader.Err(); err != nil {
				logrus.Errorf("Failed to read line: %v", err)
				return
			}

			input = strings.TrimSpace(input)

			configs, err := goech.ECHConfigListFromBase64(input)
			if err != nil {
				logrus.Errorf("Unable to parse base64 input to ECH config list: %v", err)
				return
			}

			ech.LogEchConfigs(fmt.Sprintf("Parsed: %s", input), configs...)

		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.echme.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
