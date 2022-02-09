package sentinel

import (
	"fmt"
	"log"
	"strings"
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

func resourceSentinelDataConnectorMicrosoftThreatIntelligence() *pluginsdk.Resource {
	return &pluginsdk.Resource{
		Create: resourceSentinelDataConnectorMicrosoftThreatIntelligenceCreateUpdate,
		Read:   resourceSentinelDataConnectorMicrosoftThreatIntelligenceRead,
		Update: resourceSentinelDataConnectorMicrosoftThreatIntelligenceCreateUpdate,
		Delete: resourceSentinelDataConnectorMicrosoftThreatIntelligenceDelete,

		Importer: pluginsdk.ImporterValidatingResourceIdThen(func(id string) error {
			_, err := parse.DataConnectorID(id)
			return err
		}, importSentinelDataConnector(securityinsight.DataConnectorKindMicrosoftThreatIntelligence)),

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

			"tenant_id": {
				Type:         pluginsdk.TypeString,
				Optional:     true,
				Computed:     true,
				ForceNew:     true,
				ValidateFunc: validation.IsUUID,
			},

			"bing_safety_phishing_url": {
				Type:     pluginsdk.TypeBool,
				Optional: true,
				Default:  true,
			},

			"microsoft_emerging_threat_feed": {
				Type:     pluginsdk.TypeBool,
				Optional: true,
				Default:  true,
			},
		},
	}
}

func resourceSentinelDataConnectorMicrosoftThreatIntelligenceCreateUpdate(d *pluginsdk.ResourceData, meta interface{}) error {
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
			return tf.ImportAsExistsError("azurerm_sentinel_data_connector_microsoft_threat_intelligence", id.ID())
		}
	}

	tenantId := d.Get("tenant_id").(string)
	if tenantId == "" {
		tenantId = meta.(*clients.Client).Account.TenantId
	}

	bingSafetyPhishingURLEnabled := d.Get("bing_safety_phishing_url").(bool)
	microsoftEmergingThreatFeedEnabled := d.Get("microsoft_emerging_threat_feed").(bool)

	// Service will not create the DC in case non of the toggle is enabled.
	if !bingSafetyPhishingURLEnabled && !microsoftEmergingThreatFeedEnabled {
		return fmt.Errorf("either `bing_safety_phishing_url` or `microsoft_emerging_threat_feed` should be `true`")
	}

	bingSafetyPhishingURLState := securityinsight.DataTypeStateEnabled
	if !bingSafetyPhishingURLEnabled {
		bingSafetyPhishingURLState = securityinsight.DataTypeStateDisabled
	}

	microsoftEmergingThreatFeedState := securityinsight.DataTypeStateEnabled
	if !microsoftEmergingThreatFeedEnabled {
		microsoftEmergingThreatFeedState = securityinsight.DataTypeStateDisabled
	}
	//todo: add lookback period configuration
	param := securityinsight.MSTIDataConnector{
		Name: &name,
		MSTIDataConnectorProperties: &securityinsight.MSTIDataConnectorProperties{
			TenantID: &tenantId,
			DataTypes: &securityinsight.MSTIDataConnectorDataTypes{
				BingSafetyPhishingURL: &securityinsight.MSTIDataConnectorDataTypesBingSafetyPhishingURL{
					State: bingSafetyPhishingURLState,
				},
				MicrosoftEmergingThreatFeed: &securityinsight.MSTIDataConnectorDataTypesMicrosoftEmergingThreatFeed{
					State: microsoftEmergingThreatFeedState,
				},
			},
		},
		Kind: securityinsight.KindBasicDataConnectorKindThreatIntelligence,
	}

	if !d.IsNewResource() {
		resp, err := client.Get(ctx, id.ResourceGroup, id.WorkspaceName, name)
		if err != nil {
			return fmt.Errorf("retrieving %s: %+v", id, err)
		}

		dc, ok := resp.Value.(securityinsight.MSTIDataConnector)
		if !ok {
			return fmt.Errorf("%s was not a Microsoft Threat Intelligence Data Connector", id)
		}
		param.Etag = dc.Etag
	}

	if _, err = client.CreateOrUpdate(ctx, id.ResourceGroup, id.WorkspaceName, id.Name, param); err != nil {
		return fmt.Errorf("creating %s: %+v", id, err)
	}

	d.SetId(id.ID())

	return resourceSentinelDataConnectorMicrosoftThreatIntelligenceRead(d, meta)
}

func resourceSentinelDataConnectorMicrosoftThreatIntelligenceRead(d *pluginsdk.ResourceData, meta interface{}) error {
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

	dc, ok := resp.Value.(securityinsight.MSTIDataConnector)
	if !ok {
		return fmt.Errorf("%s was not a Microsoft Threat Intelligence Data Connector", id)
	}

	d.Set("name", id.Name)
	d.Set("log_analytics_workspace_id", workspaceId.ID())
	d.Set("tenant_id", dc.TenantID)

	var (
		bingSafetyPhishingURLEnabled       bool
		microsoftEmergingThreatFeedEnabled bool
	)
	if dt := dc.DataTypes; dt != nil {
		if bingSafetyPhishingURL := dt.BingSafetyPhishingURL; bingSafetyPhishingURL != nil {
			bingSafetyPhishingURLEnabled = strings.EqualFold(string(bingSafetyPhishingURL.State), string(securityinsight.DataTypeStateEnabled))
		}

		if microsoftEmergingThreatFeed := dt.MicrosoftEmergingThreatFeed; microsoftEmergingThreatFeed != nil {
			microsoftEmergingThreatFeedEnabled = strings.EqualFold(string(microsoftEmergingThreatFeed.State), string(securityinsight.DataTypeStateEnabled))
		}
	}
	d.Set("microsoft_emerging_threat_feed", microsoftEmergingThreatFeedEnabled)
	d.Set("bing_safety_phishing_url", bingSafetyPhishingURLEnabled)

	return nil
}

func resourceSentinelDataConnectorMicrosoftThreatIntelligenceDelete(d *pluginsdk.ResourceData, meta interface{}) error {
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
