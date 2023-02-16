package composition

import (
	"fmt"
	"strings"

	"github.com/gertd/go-pluralize"

	"github.com/bearer/curio/new/detector/implementation/custom"
	"github.com/bearer/curio/new/detector/implementation/generic/datatype"
	detectortypes "github.com/bearer/curio/new/detector/types"
	"github.com/bearer/curio/new/language"
	"github.com/bearer/curio/pkg/commands/process/settings"
	reportdetections "github.com/bearer/curio/pkg/report/detections"
	"github.com/bearer/curio/pkg/report/detectors"
	"github.com/bearer/curio/pkg/report/schema"
	"github.com/bearer/curio/pkg/report/source"
	"github.com/bearer/curio/pkg/util/file"
	"github.com/bearer/curio/pkg/util/output"
)

func CompileRules(config *settings.Config) (map[string][]detectortypes.Detector, error) {
	output.StdErrLogger().Msg("Compiling rules")
	bar := output.GetProgressBar(len(config.Rules), *config, "rules")
	defer bar.Close()

	return CompileRulesInternal(config.Rules, func() error {
		if err := bar.Add(1); err != nil {
			return fmt.Errorf("failed to write progress bar %w", err)
		}

		return nil
	})
}

func CompileRulesInternal(rules map[string]*settings.Rule, progress func() error) (map[string][]detectortypes.Detector, error) {
	result := make(map[string][]detectortypes.Detector)

	cleanup := func() {
		for _, detectors := range result {
			for _, detector := range detectors {
				detector.Close()
			}
		}
	}

	for ruleName, rule := range rules {
		for _, languageName := range rule.Languages {
			detector, err := createDetectorForRule(rule, languageName)
			if err != nil {
				cleanup()
				return nil, fmt.Errorf("failed to compile rule %s: %s", ruleName, err)
			}

			result[languageName] = append(result[languageName], detector)

			if progress != nil {
				if err := progress(); err != nil {
					cleanup()
					return nil, err
				}
			}
		}
	}

	return result, nil
}

func createDetectorForRule(rule *settings.Rule, languageName string) (detectortypes.Detector, error) {
	lang, err := language.Get(languageName)
	if err != nil {
		return nil, err
	}

	return custom.New(lang, rule.Id, rule.Patterns)
}

func ReportDetections(report reportdetections.ReportDetection, file *file.FileInfo, detections []*detectortypes.Detection) {
	pluralizer := pluralize.NewClient()

	for _, detection := range detections {
		data := detection.Data.(custom.Data)

		if len(data.Datatypes) == 0 {
			report.AddDetection(reportdetections.TypeCustomRisk,
				detectors.Type(detection.DetectorType),
				source.New(
					file,
					file.Path,
					detection.MatchNode.LineNumber(),
					detection.MatchNode.ColumnNumber(),
					data.Pattern,
				),
				schema.Parent{
					LineNumber: detection.MatchNode.LineNumber(),
					Content:    detection.MatchNode.Content(),
				})
		}

		for _, datatypeDetection := range data.Datatypes {
			datatypeData := datatypeDetection.Data.(datatype.Data)

			report.AddDetection(
				reportdetections.TypeCustomClassified,
				detectors.Type(detection.DetectorType),
				source.New(
					file,
					file.Path,
					datatypeDetection.MatchNode.LineNumber(),
					datatypeDetection.MatchNode.ColumnNumber(),
					"",
				),
				schema.Schema{
					ObjectName:           datatypeData.Name,
					NormalizedObjectName: pluralizer.Singular(strings.ToLower(datatypeData.Name)),
					Classification:       datatypeData.Classification,
					Parent: &schema.Parent{
						LineNumber: detection.MatchNode.LineNumber(),
						Content:    detection.MatchNode.Content(),
					},
				},
			)

			for _, property := range datatypeData.Properties {

				report.AddDetection(
					reportdetections.TypeCustomClassified,
					detectors.Type(detection.DetectorType),
					source.New(
						file,
						file.Path,
						property.Detection.MatchNode.LineNumber(),
						property.Detection.MatchNode.ColumnNumber(),
						"",
					),
					schema.Schema{
						ObjectName:           datatypeData.Name,
						NormalizedObjectName: pluralizer.Singular(strings.ToLower(property.Name)),
						FieldName:            property.Name,
						NormalizedFieldName:  pluralizer.Singular(strings.ToLower(property.Name)),
						Classification:       property.Classification,
						Parent: &schema.Parent{
							LineNumber: detection.MatchNode.LineNumber(),
							Content:    detection.MatchNode.Content(),
						},
					},
				)
			}
		}
	}

}
