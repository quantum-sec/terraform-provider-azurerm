package sentinel

import (
	"fmt"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/preview/securityinsight/mgmt/2021-09-01-preview/securityinsight"
	"github.com/hashicorp/terraform-provider-azurerm/helpers/tf"
	"github.com/hashicorp/terraform-provider-azurerm/internal/clients"
	loganalyticsParse "github.com/hashicorp/terraform-provider-azurerm/internal/services/loganalytics/parse"
	loganalyticsValidate "github.com/hashicorp/terraform-provider-azurerm/internal/services/loganalytics/validate"
	"github.com/hashicorp/terraform-provider-azurerm/internal/services/sentinel/parse"
	"github.com/hashicorp/terraform-provider-azurerm/internal/tf/pluginsdk"
	"github.com/hashicorp/terraform-provider-azurerm/internal/tf/validation"
	"github.com/hashicorp/terraform-provider-azurerm/internal/timeouts"
	"github.com/hashicorp/terraform-provider-azurerm/utils"
)

func resourceSentinelDataConnectorAwsS3() *pluginsdk.Resource {
	return &pluginsdk.Resource{
		Create: resourceSentinelDataConnectorAwsS3CreateUpdate,
		Read:   resourceSentinelDataConnectorAwsS3Read,
		Update: resourceSentinelDataConnectorAwsS3CreateUpdate,
		Delete: resourceSentinelDataConnectorAwsS3Delete,

		Importer: pluginsdk.ImporterValidatingResourceIdThen(func(id string) error {
			_, err := parse.DataConnectorID(id)
			return err
		}, importSentinelDataConnector(securityinsight.DataConnectorKindAmazonWebServicesS3)),

		Timeouts: &pluginsdk.ResourceTimeout{
			Create: pluginsdk.DefaultTimeout(30 * time.Minute),
			Read:   pluginsdk.DefaultTimeout(5 * time.Minute),
			Update: pluginsdk.DefaultTimeout(30 * time.Minute),
			Delete: pluginsdk.DefaultTimeout(30 * time.Minute),
		},

		Schema: map[string]*pluginsdk.Schema{
			"name": {
				Type:         pluginsdk.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},

			"log_analytics_workspace_id": {
				Type:         pluginsdk.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: loganalyticsValidate.LogAnalyticsWorkspaceID,
			},

			"role_arn": {
				Type:         pluginsdk.TypeString,
				Required:     true,
				ValidateFunc: validation.StringIsNotEmpty,
			},

			"destination_table": {
				Type:     pluginsdk.TypeString,
				Required: true,
				//ValidateFunc: validation.StringInSlice([]string{
				//	"AWSCloudTrail",
				//	"AWSVPCFlow",
				//	"AWSGuardDuty",
				//}, false),
				ValidateFunc: validation.StringIsNotEmpty,
			},

			"sqs_urls": {
				Type:         pluginsdk.TypeList,
				Required:     true,
				ValidateFunc: validation.ListOfUniqueStrings,
			},
		},
	}
}

func resourceSentinelDataConnectorAwsS3CreateUpdate(d *pluginsdk.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).Sentinel.DataConnectorsClient
	ctx, cancel := timeouts.ForCreateUpdate(meta.(*clients.Client).StopContext, d)
	defer cancel()

	workspaceId, err := loganalyticsParse.LogAnalyticsWorkspaceID(d.Get("log_analytics_workspace_id").(string))
	if err != nil {
		return err
	}
	name := d.Get("name").(string)
	id := parse.NewDataConnectorID(workspaceId.SubscriptionId, workspaceId.ResourceGroup, workspaceId.WorkspaceName, name)

	if d.IsNewResource() {
		resp, err := client.Get(ctx, id.ResourceGroup, id.WorkspaceName, name)
		if err != nil {
			if !utils.ResponseWasNotFound(resp.Response) {
				return fmt.Errorf("checking for existing %s: %+v", id, err)
			}
		}

		if !utils.ResponseWasNotFound(resp.Response) {
			return tf.ImportAsExistsError("azurerm_sentinel_data_connector_aws_s3", id.ID())
		}
	}

	param := securityinsight.AwsS3DataConnector{
		Name: &name,
		AwsS3DataConnectorProperties: &securityinsight.AwsS3DataConnectorProperties{
			RoleArn:          utils.String(d.Get("role_arn").(string)),
			DestinationTable: utils.String(d.Get("destination_table").(string)),
			SqsUrls:          utils.List(d.Get("sqs_urls").([]string)),
			DataTypes: &securityinsight.AwsS3DataConnectorDataTypes{
				Logs: &securityinsight.AwsS3DataConnectorDataTypesLogs{
					State: securityinsight.DataTypeStateEnabled,
				},
			},
		},
		Kind: securityinsight.KindBasicDataConnectorKindAmazonWebServicesS3,
	}

	if !d.IsNewResource() {
		resp, err := client.Get(ctx, id.ResourceGroup, id.WorkspaceName, name)
		if err != nil {
			return fmt.Errorf("retrieving %s: %+v", id, err)
		}

		dc, ok := resp.Value.(securityinsight.AwsS3DataConnector)
		if !ok {
			return fmt.Errorf("%s was not an AWS S3 Data Connector", id)
		}
		param.Etag = dc.Etag
	}

	if _, err = client.CreateOrUpdate(ctx, id.ResourceGroup, id.WorkspaceName, id.Name, param); err != nil {
		return fmt.Errorf("creating %s: %+v", id, err)
	}

	d.SetId(id.ID())

	return resourceSentinelDataConnectorAwsS3Read(d, meta)
}

func resourceSentinelDataConnectorAwsS3Read(d *pluginsdk.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).Sentinel.DataConnectorsClient
	ctx, cancel := timeouts.ForRead(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := parse.DataConnectorID(d.Id())
	if err != nil {
		return err
	}
	workspaceId := loganalyticsParse.NewLogAnalyticsWorkspaceID(id.SubscriptionId, id.ResourceGroup, id.WorkspaceName)

	resp, err := client.Get(ctx, id.ResourceGroup, id.WorkspaceName, id.Name)
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			log.Printf("[DEBUG] %s was not found - removing from state!", id)
			d.SetId("")
			return nil
		}

		return fmt.Errorf("retrieving %s: %+v", id, err)
	}

	dc, ok := resp.Value.(securityinsight.AwsS3DataConnector)
	if !ok {
		return fmt.Errorf("%s was not an AWS S3 Data Connector", id)
	}

	d.Set("name", id.Name)
	d.Set("log_analytics_workspace_id", workspaceId.ID())
	if prop := dc.AwsS3DataConnectorProperties; prop != nil {
		d.Set("role_arn", prop.RoleArn)
		d.Set("destination_table", prop.DestinationTable)
		d.Set("sqs_urls", prop.SqsUrls)
	}

	return nil
}

func resourceSentinelDataConnectorAwsS3Delete(d *pluginsdk.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client).Sentinel.DataConnectorsClient
	ctx, cancel := timeouts.ForDelete(meta.(*clients.Client).StopContext, d)
	defer cancel()

	id, err := parse.DataConnectorID(d.Id())
	if err != nil {
		return err
	}

	if _, err = client.Delete(ctx, id.ResourceGroup, id.WorkspaceName, id.Name); err != nil {
		return fmt.Errorf("deleting %s: %+v", id, err)
	}

	return nil
}
