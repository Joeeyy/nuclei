package dingtalkbot

import (
	"fmt"

	robot "github.com/iaping/go-dingtalk-robot"
	robotMessage "github.com/iaping/go-dingtalk-robot/message"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/retryablehttp-go"
)

type Integration struct {
	dingtalkBot *robot.Robot
	options     *Options
}

// Options contains the configuration options for dingtalkBot client
type Options struct {
	AccessToken string `yaml:"dingtalk-robot-token"`
	AuthKey     string `yaml:"dingtalk-robot-authKey"`
	HttpClient  *retryablehttp.Client
}

// New creates a new dingtalk bot message Integration client based on options
func New(options *Options) (*Integration, error) {
	dingtalkBot := robot.New(options.AccessToken, options.AuthKey)

	return &Integration{dingtalkBot: dingtalkBot, options: options}, nil
}

func (i *Integration) CreateIssue(event *output.ResultEvent) error {
	actionCard := robotMessage.NewActionCard()
	actionCard.SetTitle("Here it comes d.b")
	actionCard.SetText(fmt.Sprintf(`
  ## **PATROL |d- .-b|**
  Time: %s  
  RuleName: %s  
  RuleType: %s  
  Severity: %s  
  Target: %s  
  Author: %s  
  tags: %s  
	`, event.Timestamp.Format("2006-01-02 15:04:05"), event.Info.Name, event.Type, event.Info.SeverityHolder.Severity, event.Host, event.Info.Authors, event.Info.Tags))
	// actionCard.SetContent(fmt.Sprintf("%s", event))
	gologger.Info().Msgf("template: %s", event.Template)
	gologger.Info().Msgf("CURLCommand: %s", event.CURLCommand)
	gologger.Info().Msgf("ExtractorName: %s", event.ExtractorName)
	gologger.Info().Msgf("Host: %s", event.Host)
	gologger.Info().Msgf("IP: %s", event.IP)
	gologger.Info().Msgf("Matched: %s", event.Matched)
	gologger.Info().Msgf("MatcherName: %s", event.MatcherName)
	gologger.Info().Msgf("Path: %s", event.Path)
	gologger.Info().Msgf("Request: %s", event.Request)
	gologger.Info().Msgf("Response: %s", event.Response)
	gologger.Info().Msgf("TemplateID: %s", event.TemplateID)
	gologger.Info().Msgf("templatePath: %s", event.TemplatePath)
	gologger.Info().Msgf("templateURL: %s", event.TemplateURL)
	gologger.Info().Msgf("timestamp: %s", event.Timestamp)
	gologger.Info().Msgf("Type: %s", event.Type)
	gologger.Info().Msgf("ExtractedResults: %s", event.ExtractedResults)
	gologger.Info().Msgf("Info.Authors: %s", event.Info.Authors)
	gologger.Info().Msgf("Info.Name: %s", event.Info.Name)
	gologger.Info().Msgf("Info.Tags: %s", event.Info.Tags)
	gologger.Info().Msgf("Info.Description: %s", event.Info.Description)
	gologger.Info().Msgf("Info.Reference: %s", event.Info.Reference)
	gologger.Info().Msgf("Info.Remediation: %s", event.Info.Remediation)
	gologger.Info().Msgf("Info.Classification.CVEID: %s", event.Info.Classification)
	gologger.Info().Msgf("Info.Severityholder.Severity: %s", event.Info.SeverityHolder.Severity)
	gologger.Info().Msgf("Info.Metadata: %s", event.Info.Metadata)
	gologger.Info().Msgf("FileToIndexPostion: %s", event.FileToIndexPosition)
	gologger.Info().Msgf("Info: %s", event.Info)
	gologger.Info().Msgf("interaction: %s", event.Interaction)
	gologger.Info().Msgf("Lines: %s", event.Lines)
	gologger.Info().Msgf("MatcherStatus: %s", event.MatcherStatus)
	gologger.Info().Msgf("MataData: %s", event.Metadata)
	resp, err := i.dingtalkBot.Send(actionCard)
	if err == nil {
		fmt.Println("result:", resp.IsSuccess(), "code:", resp.GetCode(), "message:", resp.GetMessage())
	}
	return nil
}
