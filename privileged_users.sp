// Tier 0 and Tier 1 privileged role IDs from Azure, Entra, and MS Graph
// These roles grant elevated privileges that require additional security monitoring

locals {
  tier0_role_ids = [
    // Azure roles - Tier 0
    "0f37683f-2463-46b6-9ce7-9b788b988ba2", // App Compliance Automation Administrator
    "f353d9bd-d4a6-484e-a77a-8050b599b867", // Automation Contributor
    "b78c5d69-af96-48a3-bf8d-a8b4d589de94", // Azure AI Administrator
    "0ab0b1a8-8aac-4efd-b8c2-3ee1fb270be8", // Azure Kubernetes Service Cluster Admin Role
    "4abbcc35-e782-43d8-92c5-2d3f1bd2253f", // Azure Kubernetes Service Cluster User Role
    "ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8", // Azure Kubernetes Service Contributor Role
    "3498e952-d568-435e-9b2c-8d77e338d7f7", // Azure Kubernetes Service RBAC Admin
    "b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b", // Azure Kubernetes Service RBAC Cluster Admin
    "a7ffa36f-339b-4b5c-8bdf-e2c188b2c0eb", // Azure Kubernetes Service RBAC Writer
    "25fbc0a9-bd7c-42a3-aa1a-3b75d497ee68", // Cognitive Services Contributor
    "a001fd3d-188f-4b5d-821b-7da978bf7442", // Cognitive Services OpenAI Contributor
    "b24988ac-6180-42a0-ab88-20f7382dd24c", // Contributor
    "082f0a83-3be5-4ba1-904c-961cca79b387", // Desktop Virtualization Contributor
    "a959dbd1-f747-45e3-8ba6-dd80f235f97c", // Desktop Virtualization Virtual Machine Contributor
    "5e93ba01-8f92-4c7a-b12a-801e3df23824", // Kubernetes Agent Operator
    "d5a2ae44-610b-4500-93be-660a0c5f5ca6", // Kubernetes Agentless Operator
    "87a39d53-fc1b-424a-814c-f7e04687dc9e", // Logic App Contributor
    "ad710c24-b039-4e85-a019-deb4a06e8570", // Logic Apps Standard Contributor (Preview)
    "f1a07417-d97a-45cb-824c-7a7467783830", // Managed Identity Operator
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", // Owner
    "a8889054-8d42-49c9-bc1c-52486c10e7cd", // Reservations Administrator
    "36243c78-bf99-498c-9df9-86d9f8d28608", // Resource Policy Contributor
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168", // Role Based Access Control Administrator
    "fb1c8493-542b-48eb-b624-b4c8fea62acd", // Security Admin
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", // User Access Administrator
    "1c0163c0-47e6-4577-8991-ea5c82e286e4", // Virtual Machine Administrator Login
    "9980e02c-c2be-4d73-94e8-173b1dc7cf3c", // Virtual Machine Contributor
    "fb879df8-f326-4884-b1cf-06f3ad86be52", // Virtual Machine User Login
    "de139f84-1756-47ae-9be6-808fbbe84772", // Website Contributor
    // Entra ID roles - Tier 0
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f", // Authentication Administrator
    "e3973bdf-4987-49ae-837a-ba8e231c7286", // Azure DevOps Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", // Conditional Access Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7", // Cloud Application Administrator
    "9360feb5-f418-4baa-8175-e2a00bac4301", // Directory Writers
    "8329153b-31d0-4727-b945-745eb3bc5f31", // Domain Name Administrator
    "be2f45a1-457d-42af-a067-6ec1fa63bc45", // External Identity Provider Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de", // Exchange Administrator
    "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
    "fdd7a751-b60b-444a-984c-02652fe8fa1c", // Groups Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8", // Helpdesk Administrator
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", // Hybrid Identity Administrator
    "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e", // Identity Governance Administrator
    "3a2c62db-5318-420d-8d74-23affee5d9d5", // Intune Administrator
    "b5a8dcf3-09d5-43a9-a639-8e29ef291470", // Knowledge Administrator
    "744ec460-397e-42ad-a462-8b3f9747a02c", // Knowledge Manager
    "59d46f88-662b-457b-bceb-5c3809e5908f", // Lifecycle Workflows Administrator
    "4ba39ca4-527c-499a-b93d-d9b492c50246", // Partner Tier1 Support
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8", // Partner Tier2 Support
    "966707d0-3269-4727-9be2-8c3a10f19b9d", // Password Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", // Privileged Authentication Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", // SharePoint Administrator
    "69091246-20e8-4a56-aa4d-066075b2a7a8", // Teams Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator
    "11451d60-acb2-45eb-a7d6-43d0f0125c13", // Windows 365 Administrator
    "810a2642-a034-447f-a5e8-41beaa378541", // Yammer Administrator
    // MS Graph permissions - Tier 0
    "5eb59dd3-1da2-4329-8733-9dabdc435916", // AdministrativeUnit.ReadWrite.All
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9", // Application.ReadWrite.All
    "18a4783c-866b-4cc7-a460-3d5e5662c884", // Application.ReadWrite.OwnedBy
    "06b708a9-e830-4db3-a914-8e69da51d44f", // AppRoleAssignment.ReadWrite.All
    "cc13eba4-8cd8-44c6-b4d4-f93237adce58", // DelegatedAdminRelationship.ReadWrite.All
    "9241abd9-d0e6-425a-bd4f-47ba86e767a4", // DeviceManagementConfiguration.ReadWrite.All
    "e330c4f0-4170-414e-a55a-2f022ec2b57b", // DeviceManagementRBAC.ReadWrite.All
    "9255e99d-faf5-445e-bbf7-cb71482737c4", // DeviceManagementScripts.ReadWrite.All
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7", // Directory.ReadWrite.All
    "7e05723c-0bb0-42da-be95-ae9f08a6e53c", // Domain.ReadWrite.All
    "9acd699f-1e81-4958-b001-93b1d2506e19", // EntitlementManagement.ReadWrite.All
    "62a82d76-70ea-41e2-9197-370581804d09", // Group.ReadWrite.All
    "dbaae8cf-10b5-4b86-a4a1-f871c94c6695", // GroupMember.ReadWrite.All
    "292d869f-3427-49a8-9dab-8c70152b74e9", // Organization.ReadWrite.All
    "29c18626-4985-4dcd-85c0-193eef327366", // Policy.ReadWrite.AuthenticationMethod
    "01c0a623-fc9b-48e9-b794-0756f8e8f067", // Policy.ReadWrite.ConditionalAccess
    "a402ca1c-2696-4531-972d-6e5ee4aa11ea", // Policy.ReadWrite.PermissionGrant
    "854d9ab1-6657-4ec8-be45-823027bcd009", // PrivilegedAccess.ReadWrite.AzureAD
    "2f6817f8-7b12-4f0f-bc18-eeaf60705a9e", // PrivilegedAccess.ReadWrite.AzureADGroup
    "6f9d5abc-2db6-400b-a267-7de22a40fb87", // PrivilegedAccess.ReadWrite.AzureResources
    "41202f2c-f7ab-45be-b001-85c9728b9d69", // PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup
    "618b6020-bca8-4de6-99f6-ef445fa4d857", // PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup
    "dd199f4a-f148-40a4-a2ec-f0069cc799ec", // RoleAssignmentSchedule.ReadWrite.Directory
    "fee28b28-e1f3-4841-818e-2704dc62245f", // RoleEligibilitySchedule.ReadWrite.Directory
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8", // RoleManagement.ReadWrite.Directory
    "b38dcc4d-a239-4ed6-aa84-6c65b284f97c", // RoleManagementPolicy.ReadWrite.AzureADGroup
    "31e08e0a-d3f7-4ca2-ac39-7343fb83e8ad", // RoleManagementPolicy.ReadWrite.Directory
    "af2bf46f-7bf1-4be3-8bad-e17e279e8462", // SecurityIdentitiesActions.ReadWrite.All
    "7fc588a2-ea2d-4d1f-bcf7-33c324b149b8", // SignInIdentifier.ReadWrite.All
    "9b50c33d-700f-43b1-b2eb-87e89b703581", // Synchronization.ReadWrite.All
    "eccc023d-eccf-4e7b-9683-8813ab36cecc", // User.DeleteRestore.All
    "3011c876-62b7-4ada-afa2-506cbbecc68c", // User.EnableDisableAccount.All
    "741f803b-c850-494e-b5df-cde7c675a1ca", // User.ReadWrite.All
    "cc117bb9-00cf-4eb8-b580-ea2a878fe8f7", // User-PasswordProfile.ReadWrite.All
    "50483e42-d915-4231-9639-7fdb7fd190e5", // UserAuthenticationMethod.ReadWrite.All
  ]

  tier1_role_ids = [
    // Azure roles - Tier 1
    "8311e382-0749-4cb8-b61a-304f252e45ec", // AcrPush
    "5ae67dd6-50cb-40e7-96ff-dc2bfa4b606b", // App Configuration Data Owner
    "516239f1-63e1-4d78-a4de-a74fb236a071", // App Configuration Data Reader
    "3afb7f49-54cb-416e-8c09-6dc049efa503", // Azure AI Inference Deployment Operator
    "f526a384-b230-433a-b45c-95f59c4a2dec", // Azure Event Hubs Data Owner
    "a638d3c7-ab3a-418d-83e6-5f17a39d4fde", // Azure Event Hubs Data Receiver
    "2b629674-e913-4c01-ae53-ef4638d8f975", // Azure Event Hubs Data Sender
    "7f6c6a51-bcf8-42ba-9220-52d62157d7db", // Azure Kubernetes Service RBAC Reader
    "090c5cfd-751d-490a-894a-3ce6f1109419", // Azure Service Bus Data Owner
    "69a216fc-b8fb-44d8-bc22-1f3c2cd27a39", // Azure Service Bus Data Sender
    "4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0", // Azure Service Bus Data Receiver
    "8480c0f0-4509-4229-9339-7c10018cb8c4", // Defender CSPM Storage Scanner Operator
    "0f641de8-0b88-4198-bdef-bd8b45ceba96", // Defender for Storage Scanner Operator
    "7efff54f-a5b4-42b5-a1c5-5411624893ce", // Disk Snapshot Contributor
    "befefa01-2a29-4197-83a8-272ff33ce314", // DNS Zone Contributor
    "eeaeda52-9324-47f6-8069-5d5bade478b2", // Domain Services Contributor
    "1e241071-0855-49ea-94dc-649edcd759de", // EventGrid Contributor
    "d5a91429-5739-47e2-a06b-3470a27159e7", // EventGrid Data Sender
    "22926164-76b3-42b3-bc55-97df8dab3e41", // Grafana Admin
    "00482a5a-887f-4fb3-b363-3b7fe8e74483", // Key Vault Administrator
    "db79e9a7-68ee-4b58-9aeb-b90e7c24fcba", // Key Vault Certificate User
    "a4417e6f-fecd-4de8-b567-7b0420556985", // Key Vault Certificates Officer
    "f25e0fa2-a7c8-4377-a976-54943a77a395", // Key Vault Contributor
    "8b54135c-b56d-4d72-a534-26097cfdc8d8", // Key Vault Data Access Administrator
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7", // Key Vault Secrets Officer
    "4633458b-17de-408a-b874-0445c86b69e6", // Key Vault Secrets User
    "92aaf0da-9dab-42b6-94a3-d43ce8d16293", // Log Analytics Contributor
    "515c2055-d9d4-4321-b1b9-bd0c9a0f79fe", // Logic App Operator
    "523776ba-4eb2-4600-a3c8-f2dc93da4bdb", // Logic Apps Standard Developer (Preview)
    "b70c96e9-66fe-4c09-b6e7-c98e69c98555", // Logic Apps Standard Operator (Preview)
    "4accf36b-2c05-432f-91c8-5c532dff4c73", // Logic Apps Standard Reader (Preview)
    "f4c81013-99ee-4d62-a7ee-b3f1f648599a", // Microsoft Sentinel Automation Contributor
    "51d6186e-6489-4900-b93f-92e23144cca5", // Microsoft Sentinel Playbook Operator
    "b12aa53e-6015-4669-85d0-8515ebb3ae7f", // Private DNS Zone Contributor
    "4d97b98b-1d4f-4787-a291-c67834d212e7", // Network Contributor
    "acdd72a7-3385-48ef-bd42-f606fba81ae7", // Reader
    "c12c1c16-33a1-487b-954d-41c89c60f349", // Reader and Data Access
    "e0f68234-74aa-48ed-b826-c38b57376e17", // Redis Cache Contributor
    "e5e2a7ff-d759-4cd2-bb51-3152d37e2eb1", // Storage Account Backup Contributor
    "17d1049b-9a84-46fb-8f53-869881c3d3ab", // Storage Account Contributor
    "81a9662b-bebf-436f-a333-f67b29880f12", // Storage Account Key Operator Service Role
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe", // Storage Blob Data Contributor
    "b7e6dc6d-f1e8-4753-8033-0f276bb0955b", // Storage Blob Data Owner
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1", // Storage Blob Data Reader
    "db58b8e5-c6ad-4a2a-8342-4190687cbf4a", // Storage Blob Delegator
    "69566ab7-960f-475b-8e7c-b3118f30c6bd", // Storage File Data Privileged Contributor
    "b8eda974-7b85-4f76-af95-65846b26df6d", // Storage File Data Privileged Reader
    "0c867c2a-1d8c-454a-a3db-ab2ea1bdc8bb", // Storage File Data SMB Share Contributor
    "a7264617-510b-434b-a828-9731dc254ea7", // Storage File Data SMB Share Elevated Contributor
    "aba4ae5f-2193-4029-9191-0cb91df5e314", // Storage File Data SMB Share Reader
    "974c5e8b-45b9-4653-ba55-5f855dd0fb88", // Storage Queue Data Contributor
    "0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3", // Storage Table Data Contributor
    "1f135831-5bbe-4924-9016-264044c00788", // Windows 365 Network Interface Contributor
    // Entra ID roles - Tier 1
    "d2562ede-74db-457e-a7b6-544e236ebb61", // AI Administrator
    "c430b396-e693-46cc-96f3-db01bf8bb62a", // Attack Simulation Administrator
    "58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d", // Attribute Assignment Administrator
    "0526716b-113d-4c15-b2c8-68e3c22b9f80", // Authentication Policy Administrator
    "9f06204d-73c1-4d4c-880a-6edb90606fd8", // Azure AD Joined Device Local Administrator
    "7495fdc4-34c4-4d15-a289-98788ce399fd", // Azure Information Protection Administrator
    "aaf43236-0c0d-4d5f-883a-6955382ac081", // B2C IEF Keyset Administrator
    "3edaf663-341e-4475-9f94-5c398ef6c070", // B2C IEF Policy Administrator
    "b0f54661-2d74-4c50-afa3-1ec803f12efe", // Billing Administrator
    "892c5842-a9a6-463a-8041-72aa08ca3cf6", // Cloud App Security Administrator
    "7698a772-787b-4ac8-901f-60d6b08affd2", // Cloud Device Administrator
    "17315797-102d-40b4-93e0-432062caca18", // Compliance Administrator
    "e6d1a23a-da11-4be4-9570-befc86d067a7", // Compliance Data Administrator
    "d29b2b05-8046-44ba-8758-1e26182fcf32", // Directory Synchronization Accounts
    "44367163-eba1-44c3-98af-f5787879f96a", // Dynamics 365 Administrator
    "963797fb-eb3b-4cde-8ce3-5878b3f32a3f", // Dynamics 365 Business Central Administrator
    "6e591065-9bad-43ed-90f3-e9424366d2f0", // External ID User Flow Administrator
    "a9ea8996-122f-4c74-9520-8edcd192826c", // Fabric Administrator
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451", // Global Reader
    "ac434307-12b9-4fa1-a708-88bf58caabc1", // Global Secure Access Administrator
    "843318fb-79a6-4168-9e6f-aa9a07481cc4", // Global Secure Access Log Reader
    "95e79109-95c0-4d8e-aee3-d01accf2d47b", // Guest Inviter
    "2ea5ce4c-b2d8-4668-bd81-3680bd2d227a", // IoT Device Administrator
    "74ef975b-6605-40af-a5d2-b9539d836353", // Kaizala Administrator
    "4d6ac14f-3453-41d0-bef9-a3e0c569773a", // License Administrator
    "8c8b803f-96e1-4129-9349-20738d9f9652", // Microsoft 365 Migration Administrator
    "1707125e-0aa2-4d4d-8655-a7c786c76a25", // Microsoft 365 Backup Administrator
    "ee67aa9c-e510-4759-b906-227085a7fd4d", // Microsoft Graph Data Connect Administrator
    "78b0ccd1-afc2-4f92-9116-b41aedd09592", // Places Administrator
    "a92aed5d-d78a-4d16-b381-09adb37eb3b0", // On Premises Directory Sync Account
    "9d70768a-0cbc-4b4c-aea3-2e124b2477f4", // Organizational Data Source Administrator
    "507f53e4-4e52-4077-abd3-d2e1558b6ea2", // Organizational Messages Writer
    "024906de-61e5-49c8-8572-40335f1e0e10", // People Administrator
    "af78dc32-cf4d-46f9-ba4e-4428526346b5", // Permissions Management Administrator
    "11648597-926c-4cf3-9c36-bcebb0ba8dcc", // Power Platform Administrator
    "5f2222b1-57c3-48ba-8ad5-d4759f1fde6f", // Security Operator
    "5d6b6bb7-de71-4623-b4af-96380a352509", // Security Reader
    "1a7d78b6-429f-476b-b8eb-35fb715fffd4", // SharePoint Embedded Administrator
    "75941009-915a-4869-abe7-691bff18279e", // Skype for Business Administrator
    "baf37b3a-610e-45da-9e62-d9d1e5e8914b", // Teams Communications Administrator
    "f70938a0-fc10-4177-9e90-2178f8765737", // Teams Communications Support Engineer
    "3d762c5a-1b6c-493f-843e-55a3b42923d4", // Teams Devices Administrator
    "1076ac91-f3d9-41a7-a339-dcdf5f480acc", // Teams Reader
    "aa38014f-0993-46e9-9b45-30501a20909d", // Teams Telephony Administrator
    "0ec3f692-38d6-4d14-9e69-0377ca7797ad", // Viva Glint Tenant Administrator
    "92b086b3-e367-4ef2-b869-1de128fb986e", // Viva Goals Administrator
    "32696413-001a-46ae-978c-ce0f6b3620d2", // Windows Update Deployment Administrator
  ]
}

// Benchmark for Azure AD privileged users security
benchmark "azuread_privileged_users" {
  title       = "Azure AD Privileged Users Security"
  description = "Security checks for Azure AD privileged users, focusing on sign-in patterns and device security."

  children = [
    control.privileged_users_unmanaged_device_signin
  ]

  tags = {
    category = "Security"
    service  = "Azure AD"
    type     = "Benchmark"
  }
}

// Control: Detect privileged users signing in from unmanaged devices
control "privileged_users_unmanaged_device_signin" {
  title       = "Privileged Users Should Not Sign In From Unmanaged Devices"
  description = "Detects Tier 0 and Tier 1 privileged users who have successfully signed in from unmanaged devices. These sign-ins represent a security risk as unmanaged devices may not have proper security controls."
  severity    = "high"

  sql = <<-EOQ
    WITH RECURSIVE group_members AS (
      -- Base case: direct group members
      SELECT 
        g.id as group_id, 
        jsonb_array_elements_text(g.member_ids) as member_id, 
        1 as depth
      FROM azuread_group g
      WHERE jsonb_array_length(COALESCE(g.member_ids, '[]'::jsonb)) > 0
      
      UNION ALL
      
      -- Recursive case: nested groups (depth limit 20)
      SELECT 
        gm.group_id, 
        jsonb_array_elements_text(g.member_ids) as member_id, 
        gm.depth + 1
      FROM group_members gm
      JOIN azuread_group g ON g.id = gm.member_id
      WHERE gm.depth < 20
        AND jsonb_array_length(COALESCE(g.member_ids, '[]'::jsonb)) > 0
    ),
    -- Get all users who are members of privileged roles (directly or via groups)
    privileged_users AS (
      SELECT DISTINCT 
        COALESCE(gm.member_id, direct_member) as user_id,
        dr.role_template_id,
        dr.display_name as role_name,
        CASE 
          WHEN dr.role_template_id = ANY($1) THEN 'Tier 0'
          ELSE 'Tier 1'
        END as tier
      FROM azuread_directory_role dr
      CROSS JOIN LATERAL jsonb_array_elements_text(dr.member_ids) as direct_member
      LEFT JOIN group_members gm ON gm.group_id = direct_member
      WHERE dr.role_template_id = ANY($1 || $2)
    )
    SELECT
      s.id as resource,
      'alarm' as status,
      pu.role_name || ' ' || pu.tier || ' ' || s.user_principal_name || ' signed in from ' || s.ip_address || ' (' || COALESCE(s.device_detail->>'operatingSystem', 'Unknown OS') || ') to ' || s.app_display_name as reason,
      -- Additional properties for context
      jsonb_build_object(
        'user_principal_name', s.user_principal_name,
        'user_id', pu.user_id,
        'tier', pu.tier,
        'role_name', pu.role_name,
        'sign_in_time', s.created_date_time,
        'app_display_name', s.app_display_name,
        'resource_display_name', s.resource_display_name,
        'ip_address', s.ip_address,
        'operating_system', s.device_detail->>'operatingSystem',
        'browser', s.device_detail->>'browser'
      ) as dimensions
    FROM azuread_sign_in_report s
    JOIN privileged_users pu ON pu.user_id = s.user_id
    WHERE 
      -- Successful sign-in (error code 0)
      COALESCE((s.status->>'errorCode')::int, -1) = 0
      -- Device is not managed
      AND COALESCE((s.device_detail->>'isManaged')::boolean, false) = false
    ORDER BY s.created_date_time DESC;
  EOQ

  param "tier0_role_ids" {
    default = local.tier0_role_ids
  }
  
  param "tier1_role_ids" {
    default = local.tier1_role_ids
  }

  tags = {
    category = "Security"
    service  = "Azure AD"
    type     = "Control"
  }
}
