package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/retryablehttp-go"
)

type Options struct {
	Username          string `yaml:"username" validate:"required"`
	Password          string `yaml:"password" validate:"required"`
	Host              string `yaml:"host" validate:"required"`
	Port              int    `yaml:"port" validate:"required,gte=0,lte=65535"`
	Database          string `yaml:"database" validate:"required"`
	ConnectionTimeout string `yaml:"connection-timeout"`
	IndexName         string `yaml:"index-name"`
	HttpClient        *retryablehttp.Client
}

type data struct {
	Event     *output.ResultEvent `json:"event"`
	Timestamp string              `json:"@timestamp"`
}

type Exporter struct {
	options *Options
	url     string
	db      *sql.DB
}

func New(options *Options) (*Exporter, error) {
	url := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?timeout=%s", options.Username, options.Password, options.Host, options.Port, options.Database, options.ConnectionTimeout)
	db, err := sql.Open("mysql", url)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)
	return &Exporter{url: url, options: options, db: db}, nil
}

func (exporter *Exporter) Export(event *output.ResultEvent) error {
	gologger.Info().Msgf("[bittea rds expoter] executing...")
	host := event.Host
	ip := event.IP
	templateId := event.TemplateID
	templatePath := event.TemplatePath
	templateUrl := event.TemplateURL
	timestamp := event.Timestamp
	_type := event.Type
	author := event.Info.Authors.String()
	templateName := event.Template
	tags := event.Info.Tags.String()
	desc := event.Info.Description
	reference := event.Info.Reference.String()
	remediation := event.Info.Remediation
	classification := event.Info.Classification
	cveid := ""
	cweid := ""
	CVSSMetrics := ""
	if classification != nil {
		cveid = classification.CVEID.String()
		cweid = classification.CWEID.String()
		CVSSMetrics = classification.CVSSMetrics
	}
	severity := event.Info.SeverityHolder.Severity.String()
	request := event.Request
	response := event.Response
	curlCommand := event.CURLCommand
	extractorName := event.ExtractorName
	matcherName := event.MatcherName
	matched := event.Matched
	path := event.Path
	metaData := fmt.Sprintf("%s", event.Metadata)
	extractedResults := fmt.Sprintf("%s", event.ExtractedResults)
	fileToIndexPosition := fmt.Sprintf("%v", event.FileToIndexPosition)
	lines := fmt.Sprintf("%v", event.Lines)
	matcherStatus := event.MatcherStatus
	interaction := fmt.Sprintf("%s", event.Interaction)

	stmt, err := exporter.db.Prepare(`
	INSERT INTO patrol_vuls(
		host,
		ip,
		templateid,
		templatepath,
		templateurl,
		` + "`timestamp`" + `,
		type,
		templateauthor,
		templateName,
		tags,
		` + "`desc`" + `,
		reference,
		remediation,
		cveid,
		cweid,
		cvss,
		severity,
		request,
		response,
		curlcommand,
		extractorname,
		matchername,
		matched,
		path,
		metadata,
		extractedresults,
		filetoindexposition,
		` + "`lines`" + `,
		matcherstatus,
		interaction
	)
	VALUES(
		?,?,?,?,?,
		?,?,?,?,?,
		?,?,?,?,?,
		?,?,?,?,?,
		?,?,?,?,?,
		?,?,?,?,?
	)
	`)
	if err != nil {
		gologger.Error().Msgf("[bittea rds expoter] error occurred %s", err)
		return err
	}
	defer stmt.Close()
	result, err := stmt.Exec(host,
		ip,
		templateId,
		templatePath,
		templateUrl,
		timestamp,
		_type,
		author,
		templateName,
		tags,
		desc,
		reference,
		remediation,
		cveid,
		cweid,
		CVSSMetrics,
		severity,
		request,
		response,
		curlCommand,
		extractorName,
		matcherName,
		matched,
		path,
		metaData,
		extractedResults,
		fileToIndexPosition,
		lines,
		matcherStatus,
		interaction)
	if err != nil {
		gologger.Error().Msgf("[bittea rds expoter] error occurred %s", err)
		return err
	}
	gologger.Info().Msgf("[bittea rds expoter] result: %s", result)
	gologger.Info().Msgf("[bittea rds expoter] result: %s", err)

	return nil
}

func (exporter *Exporter) Close() error {
	return exporter.db.Close()
}
