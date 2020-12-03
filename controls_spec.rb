require 'yaml'
require 'date'

config_file = YAML.load(File.read(File.expand_path(File.dirname(__FILE__) + '/config.yaml')))
control_pack = config_file['id']
titles = Hash[config_file['controls'].map { |control| [control['id'], control['title']] }]

# AWS
control_id = 'darkbit-aws-9'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (u:AWS_IAM_USER)
    RETURN u.name AS name,
           u.access_key_1_last_used_date AS key_1_last_used,
           u.access_key_2_last_used_date AS key_2_last_used
  )
  users = graphdb.query(q).mapped_results
  users.each do |user|
    key_1_age = Time.parse(user.key_1_last_used) rescue Time.now.utc # rubocop:disable Style/RescueModifier
    key_2_age = Time.parse(user.key_2_last_used) rescue Time.now.utc # rubocop:disable Style/RescueModifier

    describe user.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have infrequently used access keys' do
        expect(key_1_age).to be > 90.days.ago
        expect(key_2_age).to be > 90.days.ago
      end
    end
  end
end

control_id = 'darkbit-aws-10'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (u:AWS_IAM_USER)
    RETURN u.name AS name,
           u.password_enabled AS password_enabled,
           u.mfa_active AS mfa_active
  )
  users = graphdb.query(q).mapped_results
  users.each do |user|
    has_password_and_mfa_enabled = user.password_enabled == 'true' ? user.mfa_active == 'true' : true

    describe user.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have MFA enabled if password is enabled' do
        expect(has_password_and_mfa_enabled).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-aws-11'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (a:AWS_IAM_PASSWORD_POLICY)
    RETURN a.account AS account,
           a.minimum_password_length AS minimum_password_length,
           a.require_symbols AS require_symbols,
           a.require_numbers AS require_numbers,
           a.require_uppercase_characters AS require_uppercase_characters,
           a.require_lowercase_characters AS require_lowercase_characters,
           a.expire_passwords AS expire_passwords,
           a.password_reuse_prevention AS password_reuse_prevention,
           a.max_password_age AS max_password_age
  )
  policies = graphdb.query(q).mapped_results
  policies.each do |policy|
    describe "arn:aws:::#{policy.account}/account", control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have adequate IAM password policy' do
        expect(policy.minimum_password_length.to_i).to be >= 14
        expect(policy.require_symbols).to eq('true')
        expect(policy.require_numbers).to eq('true')
        expect(policy.require_uppercase_characters).to eq('true')
        expect(policy.require_lowercase_characters).to eq('true')
        expect(policy.expire_passwords).to eq('true')
        expect(policy.password_reuse_prevention.to_i).to be >= 5
        expect(policy.max_password_age.to_i).to be <= 90
        expect(policy.max_password_age.to_i).to be > 0
      end
    end
  end
end

control_id = 'darkbit-aws-12'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (u:AWS_IAM_USER)
    WHERE u.user = '<root_account>'
    RETURN u.name AS name,
           u.access_key_1_active AS key_1_active,
           u.access_key_2_active AS key_2_active
  )
  users = graphdb.query(q).mapped_results
  users.each do |user|
    describe user.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have access keys' do
        expect(user.key_1_active).to eq('false')
        expect(user.key_2_active).to eq('false')
      end
    end
  end
end

control_id = 'darkbit-aws-13'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (u:AWS_IAM_USER)-[r:HAS_MFA_DEVICE]-(d:AWS_IAM_MFA_DEVICE)
    WHERE u.user = '<root_account>'
    RETURN u.name AS name,
           u.mfa_active AS mfa_active,
           r.virtual_mfa_token AS virtual_mfa_token
  )
  users = graphdb.query(q).mapped_results
  users.each do |user|
    describe user.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a hardware MFA device' do
        expect(user.mfa_active).to eq('true')
        expect(user.virtual_mfa_token).to_not eq('true')
      end
    end
  end
end

## TODO: map relationship to account and check across accounts
control_id = 'darkbit-aws-17'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (p:AWS_IAM_MANAGED_POLICY)
    WHERE p.name = 'arn:aws:iam::aws:policy/AWSSupportAccess'
    RETURN p.name AS name, p.attachment_count AS attachment_count
  )
  policies = graphdb.query(q).mapped_results
  policies.each do |policy|
    describe policy.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have at least one policy attachment' do
        expect(policy.attachment_count.to_i).to be >= 1
      end
    end
  end
end

control_id = 'darkbit-aws-18'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-20'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-23'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-29'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (v:AWS_VPC)-[r:HAS_FLOW_LOG]-(f:AWS_FLOW_LOG)
    RETURN v.name AS name,
           v.region AS region,
           v.account AS account,
           r.status AS flow_log_status,
           f.name AS flow_log_id
  )
  vpcs = graphdb.query(q).mapped_results
  vpcs.each do |vpc|
    describe "arn:aws:ec2:#{vpc.region}:#{vpc.account}:#{vpc.name}", control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should flow logging enabled' do
        expect(vpc.flow_log_status).to eq('ACTIVE')
        expect(vpc.flow_log_id).to_not be nil
      end
    end
  end
end

control_id = 'darkbit-aws-31'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-32'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-34'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (ecr:AWS_ECR_REPOSITORY)
    RETURN ecr.name AS name,
           ecr.scan_on_push AS scan_on_push
  )
  repos = graphdb.query(q).mapped_results
  repos.each do |repo|
    describe repo.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have scan-on-push enabled' do
        expect(repo.scan_on_push).to eq('true')
      end
    end
  end
end

control_id = 'darkbit-aws-35'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (s3:AWS_S3_BUCKET)
    RETURN s3.name AS name,
           s3.logging_bucket_target AS bucket_target,
           s3.logging_bucket_prefix AS bucket_prefix
  )
  buckets = graphdb.query(q).mapped_results
  buckets.each do |bucket|
    describe bucket.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have access control logging enabled' do
        expect(bucket.bucket_target).to_not be nil
        expect(bucket.bucket_prefix).to_not be nil
      end
    end
  end
end

control_id = 'darkbit-aws-42'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-43'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-47'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-51'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-58'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-61'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (c:AWS_EKS_CLUSTER)-[l:HAS_LOGGING_TYPE]-(t)
    RETURN c.name AS name, 
           l.enabled AS logging_enabled, 
           t.name AS logging_type
  )
  clusters_map = graphdb.query(q).mapped_results
  clusters = clusters_map.map { |c| c.name }.uniq

  clusters.each do |cluster|
    describe cluster, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have full audit logging enabled' do
        enabled = clusters_map.filter { |c| c.name == cluster }.map { |l| l.logging_enabled }.all?('true')
        expect(enabled).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-aws-67'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (ct:AWS_CLOUDTRAIL_TRAIL)
    RETURN ct.name AS name,
           ct.log_file_validation_enabled AS log_file_validation_enabled
  )

  trails = graphdb.query(q).mapped_results
  trails.each do |trail|
    describe trail.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have log file validation enabled' do
        expect(trail.log_file_validation_enabled).to eq('true')
      end
    end
  end
end

control_id = 'darkbit-aws-72'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (b:AWS_S3_BUCKET)
    RETURN b.name AS name, b.is_public AS is_public
  )
  buckets = graphdb.query(q).mapped_results
  buckets.each do |bucket|
    describe bucket.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be public' do
        expect(bucket.is_public).not_to eq('true')
        expect(bucket.is_public).to eq('false')
      end
    end
  end
end

control_id = 'darkbit-aws-75'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (k:AWS_KMS_KEY)
    RETURN k.name AS name,
           k.rotation_enabled AS rotation_enabled
  )
  keys = graphdb.query(q).mapped_results
  keys.each do |key|
    describe key.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have key rotation enabled' do
        expect(key.rotation_enabled).to eq('true')
      end
    end
  end
end

control_id = 'darkbit-aws-108'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (u:AWS_IAM_USER)
    WHERE u.user = "<root_account>"
    RETURN u.name AS name,
           u.password_last_used AS password_last_used,
           u.access_key_1_last_used_date AS key_1_last_used,
           u.access_key_2_last_used_date AS key_2_last_used
  )
  users = graphdb.query(q).mapped_results
  users.each do |user|
    password_last_used = Time.parse(user.password_last_used) rescue Time.now.utc - 99.days # rubocop:disable Style/RescueModifier
    key_1_last_used = Time.parse(user.key_1_last_used) rescue Time.now.utc - 99.days # rubocop:disable Style/RescueModifier
    key_2_last_used = Time.parse(user.key_2_last_used) rescue Time.now.utc - 99.days # rubocop:disable Style/RescueModifier

    describe user.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have recently used password or access keys' do
        expect(password_last_used).to be < 30.days.ago
        expect(key_1_last_used).to be < 30.days.ago
        expect(key_2_last_used).to be < 30.days.ago
      end
    end
  end
end

control_id = 'darkbit-aws-110'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %(
    MATCH (u:AWS_IAM_USER)
    RETURN u.name AS name,
           u.access_key_1_active AS key_1_active,
           u.access_key_2_active AS key_2_active
  )
  users = graphdb.query(q).mapped_results
  users.each do |user|
    active_keys = user.to_h.values.filter { |k| k == 'true' }
    describe user.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have more than 1 active access key' do
        expect(active_keys.count).to be <= 1
      end
    end
  end
end

control_id = 'darkbit-aws-111'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-113'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-114'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-115'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-116'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-117'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-118'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-119'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-120'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-121'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-122'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-123'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-125'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-126'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-128'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-129'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-130'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-131'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-aws-132'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# GCP
control_id = 'darkbit-gcp-6'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_IDENTITY)-[r:HAS_IAMROLE]-(p:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    WHERE r.role_name = 'roles/iam.serviceAccountUser' OR
          r.role_name = 'roles/iam.serviceAccountTokenCreator'
    RETURN c.name as name, r.role_name as role_name
  )
  identities = graphdb.query(q).mapped_results
  if identities.length > 0
    identities.each do |identity|
      describe identity.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have iam.serviceAccountUser or iam.serviceAccountTokenCreator bound at the project level' do
          expect(identity.role_name).not_to eq('roles/iam.serviceAccountUser')
          expect(identity.role_name).not_to eq('roles/iam.serviceAccountTokenCreator')
        end
      end
    end
  else
    describe 'No Bindings found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have iam.serviceAccountUser or iam.serviceAccountTokenCreator bound at the project level' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-14'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (s:GCP_COMPUTE_SUBNETWORK) 
    RETURN s.name as name, 
           s.resource_data_logConfig_enable as flow_logging, 
           s.resource_data_logConfig_flowSampling as flow_sampling, 
           s.resource_data_logConfig_metadata as metadata
  )
  subnets = graphdb.query(q).mapped_results
  if subnets.length > 0
    subnets.each do |subnet|
      describe subnet.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have full VPC Flow logging enabled' do
          expect(subnet.flow_logging).to eq('true')
          expect(subnet.flow_sampling).to eq('1')
          expect(subnet.metadata).to eq('INCLUDE_ALL_METADATA')
        end
      end
    end
  else
    describe 'No Subnets found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have full VPC Flow logging enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

# BLOCKED: Needs firewall rule deep parsing
control_id = 'darkbit-gcp-15'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-17'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (i:GCP_COMPUTE_INSTANCE)
    WHERE i.resource_data_labels_goog_gke_node IS NULL
    OPTIONAL MATCH (i)-[:HAS_NETWORKACCESSCONFIG]->(n:GCP_COMPUTE_NETWORKACCESSCONFIG)
    WHERE i.resource_data_labels_goog_gke_node IS NULL
    return i.name as name, n.type as network_type
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have a private IP' do
          expect(instance.network_type).not_to eq('ONE_TO_ONE_NAT')
        end
      end
    end
  else
    describe 'No Instances found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a private IP' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-18'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (v:GCP_COMPUTE_NETWORK)
    WHERE NOT v.resource_data_name IS NULL
    RETURN v.name as vpc_name, v.resource_data_name as friendly_name
  )
  vpcs = graphdb.query(q).mapped_results
  if vpcs.length > 0
    vpcs.each do |vpc|
      describe vpc.vpc_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be a default VPC' do
          expect(vpc.friendly_name).not_to eq('default')
        end
      end
    end
  else
    describe 'No VPCs found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be a default VPC' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-19'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sa:GCP_IAM_SERVICEACCOUNTKEY)
    WHERE sa.resource_data_keyType = "USER_MANAGED"
      and NOT sa.resource_data_validAfterTime IS NULL
    RETURN sa.name as sa_name, sa.resource_data_validAfterTime as start_time
  )
  sas = graphdb.query(q).mapped_results
  if sas.length > 0
    sas.each do |sa|
      describe sa.sa_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be older than 90 days' do
          days_old = (DateTime.now - DateTime.parse(sa.start_time)).to_i
          expect(days_old).to be <= 90
        end
      end
    end
  else
    describe 'No SA Keys found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be older than 90 days' do
        expect(true).to eq(true)
      end
    end
  end
end

# TODO: Project iam-policy
control_id = 'darkbit-gcp-20'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-22'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (instance:GCP_SQLADMIN_INSTANCE)
    RETURN instance.name as name, instance.resource_data_settings_ipConfiguration_ipv4Enabled as public
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be public' do
          expect(instance.public).to eq('false')
        end
      end
    end
  else
    describe 'No CloudSQL Instances found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be public' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-23'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (instance:GCP_SQLADMIN_INSTANCE)
    RETURN instance.name as name, instance.resource_data_settings_ipConfiguration_requireSsl as requires_ssl
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should require SSL' do
          expect(instance.requires_ssl).to eq('true')
        end
      end
    end
  else
    describe 'No CloudSQL Instances found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should require SSL' do
        expect(true).to eq(true)
      end
    end
  end
end

# BLOCKED: Needs firewall rule deep parsing
control_id = 'darkbit-gcp-26'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_COMPUTE_TARGETHTTPSPROXY and GCP_COMPUTE_TARGETSSLPROXY?
control_id = 'darkbit-gcp-33'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-38'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_networkPolicy_enabled as network_policy
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have Network Policy configured' do
          expect(cluster.network_policy).to eq('true')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have Network Policy configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-39'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    OPTIONAL MATCH (c:GCP_CONTAINER_CLUSTER)-[:HAS_MASTERAUTHORIZEDNETWORK]->(n:GCP_CONTAINER_MASTERAUTHORIZEDNETWORK)
    WHERE n.cidr_block = '0.0.0.0/0'
    RETURN c.name, c.resource_data_masterAuthorizedNetworksConfig_enabled as authorized_networks_enabled, n.cidr_block as any_ip
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should restrict access to the API' do
          expect(cluster.authorized_networks_enabled).to eq('true')
          expect(cluster.any_ip).not_to eq('0.0.0.0/0')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should restrict access to the API' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-40'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_workloadIdentityConfig_workloadPool as wi
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have Workload Identity configured' do
          expect(cluster.wi).to include('svc.id.goog')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have Workload Identity configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-41'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_NODEPOOL)-[r:HAS_SERVICEACCOUNT]->(gi:GCP_IDENTITY)
    RETURN c.name as name, gi.resource_data_email as sa_name
  )
  gkenodepools = graphdb.query(q).mapped_results
  if gkenodepools.length > 0
    gkenodepools.each do |nodepool|
      describe nodepool.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have the default ServiceAccount attached' do
          expect(nodepool.sa_name).not_to include('-compute@developer.gserviceaccount.com')
        end
      end
    end
  else
    describe 'No GKE NodePools found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have the default ServiceAccount attached' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-42'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_shieldedNodes_enabled as shielded_nodes
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have Shielded Nodes configured' do
          expect(cluster.shielded_nodes).to eq('true')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have Shielded Nodes configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-44'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_privateClusterConfig_privateEndpoint as private_endpoint
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have a Private Master Endpoint configured' do
          expect(cluster.private_endpoint).not_to be(nil)
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have a Private Master Endpoint configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-47'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_networkConfig_enableIntraNodeVisibility as intranode_visibility
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have IntraNode Visibility configured' do
          expect(cluster.intranode_visibility).to eq('true')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have IntraNode Visibility configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-48'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_loggingService as logging
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have GCP Logging configured' do
          expect(cluster.logging).to eq('logging.googleapis.com/kubernetes')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have GCP Logging configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-50'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_NODEPOOL)
    RETURN c.name as name, c.config_imageType as os
  )
  gkenodepools = graphdb.query(q).mapped_results
  if gkenodepools.length > 0
    gkenodepools.each do |nodepool|
      describe nodepool.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should use COS or COS_CONTAINERD' do
          expect(nodepool.os).to match(/^COS.*/i)
        end
      end
    end
  else
    describe 'No GKE NodePools found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should use COS or COS_CONTAINERD' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-52'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_NODEPOOL)
    RETURN c.name as name, c.management_autoRepair as autorepair
  )
  gkenodepools = graphdb.query(q).mapped_results
  if gkenodepools.length > 0
    gkenodepools.each do |nodepool|
      describe nodepool.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have autorepair enabled' do
          expect(nodepool.autorepair).to eq('true')
        end
      end
    end
  else
    describe 'No GKE NodePools found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have autorepair enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-53'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_NODEPOOL)
    RETURN c.name as name, c.management_autoUpgrade as autoupgrade
  )
  gkenodepools = graphdb.query(q).mapped_results
  if gkenodepools.length > 0
    gkenodepools.each do |nodepool|
      describe nodepool.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have autoupgrade enabled' do
          expect(nodepool.autoupgrade).to eq('true')
        end
      end
    end
  else
    describe 'No GKE NodePools found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have autoupgrade enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-55'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_ipAllocationPolicy_useIpAliases AS subnet_range_enabled
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have Subnet IP Alias Ranges configured' do
          expect(cluster.subnet_range_enabled).to eq('true')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have Subnet IP Alias Ranges configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-56'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_legacyAbac as abac
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have legacy Abac configured' do
          expect(cluster.abac).to be(nil)
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have legacy Abac configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-59'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (instance:GCP_SQLADMIN_INSTANCE)
    WHERE instance.resource_data_instanceType <> 'READ_REPLICA_INSTANCE'
    RETURN instance.name, instance.resource_data_settings_backupConfiguration_enabled as backups, instance.resource_data_settings_backupConfiguration_binaryLogEnabled as binlog_enabled
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have automatic backups configured' do
          expect(instance.backups).to eq('true')
          expect(instance.binlog_enabled).to eq('true')
        end
      end
    end
  else
    describe 'No CloudSQL Instances found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have automatic backups configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-60'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_IDENTITY { member_type: 'serviceAccount' })-[r:HAS_IAMROLE]-(p:GCP_CLOUDRESOURCEMANAGER_PROJECT)
    WHERE c.name ENDS WITH '-compute@developer.gserviceaccount.com'
    RETURN c.name as name, r.role_name as role_name
  )
  sas = graphdb.query(q).mapped_results
  if sas.length > 0
    sas.each do |sa|
      describe sa.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have Editor bound to the default service account' do
          expect(sa.role_name).not_to eq('roles/editor')
        end
      end
    end
  else
    describe 'No Binding found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have Editor bound to the default service account' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-61'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_databaseEncryption_state as encryption_state
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should encrypt secrets at rest in Etcd' do
          expect(cluster.encryption_state).to eq('ENCRYPTED')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should encrypt secrets at rest in Etcd' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-62'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (sak:GCP_IAM_SERVICEACCOUNTKEY)
    WHERE sak.resource_data_keyType = "USER_MANAGED"
    RETURN DISTINCT sak.resource_parent as sa_id
  )
  sas = graphdb.query(q).mapped_results
  if sas.length > 0
    sas.each do |sa|
      sa_id = sa.sa_id.gsub(/^\/\//, '')
      describe sa_id, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have user-managed keys' do
          expect(sa_id).to be_nil
        end
      end
    end
  else
    describe 'No User-Managed SA Keys found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have user-managed keys' do
        expect(true).to eq(true)
      end
    end
  end
end

# TODO: GCP SA and IAM
control_id = 'darkbit-gcp-63'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: IAM and GCP_CLOUDKMS_KEYRING
control_id = 'darkbit-gcp-64'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: IAM and GCP_CLOUDKMS_KEYRING
control_id = 'darkbit-gcp-65'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-66'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (key:GCP_CLOUDKMS_CRYPTOKEY)
    WHERE key.resource_data_primary_state = "ENABLED"
      AND key.resource_data_purpose = "ENCRYPT_DECRYPT"
    RETURN key.name, key.resource_data_primary_generateTime as last_generated
  )
  keys = graphdb.query(q).mapped_results
  if keys.length > 0
    keys.each do |key|
      describe key.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be older than 90 days' do
          days_old = (DateTime.now - DateTime.parse(key.last_generated)).to_i
          expect(days_old).to be <= 90
        end
      end
    end
  else
    describe 'No KMS Keys found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be older than 90 days' do
        expect(true).to eq(true)
      end
    end
  end
end

# TODO: IAM
control_id = 'darkbit-gcp-67'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: PROJECT or FOLDER GCP_LOGGING_LOGSINK
control_id = 'darkbit-gcp-72'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_CLOUDSTORAGE_BUCKET
control_id = 'darkbit-gcp-73'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_LOGGING_LOGMETRIC (suboptimal)
control_id = 'darkbit-gcp-74'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_LOGGING_LOGMETRIC (suboptimal)
control_id = 'darkbit-gcp-75'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_LOGGING_LOGMETRIC (suboptimal)
control_id = 'darkbit-gcp-76'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_LOGGING_LOGMETRIC (suboptimal)
control_id = 'darkbit-gcp-77'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_LOGGING_LOGMETRIC (suboptimal)
control_id = 'darkbit-gcp-78'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_LOGGING_LOGMETRIC (suboptimal)
control_id = 'darkbit-gcp-79'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_LOGGING_LOGMETRIC (suboptimal)
control_id = 'darkbit-gcp-80'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-81'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (v:GCP_COMPUTE_NETWORK)
    WHERE NOT v.resource_data_name IS NULL
    RETURN v.name as vpc_name, v.resource_data_IPv4Range as legacy_range
  )
  vpcs = graphdb.query(q).mapped_results
  if vpcs.length > 0
    vpcs.each do |vpc|
      describe vpc.vpc_name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not be a legacy VPC' do
          expect(vpc.legacy_range).to be_nil
        end
      end
    end
  else
    describe 'No VPCs found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not be a legacy VPC' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-82'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (zone:GCP_DNS_MANAGEDZONE)
    RETURN zone.name as name, zone.resource_data_dnssecConfig_state as state
  )
  zones = graphdb.query(q).mapped_results
  if zones.length > 0
    zones.each do |zone|
      describe zone.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have DNSSEC enabled' do
          expect(zone.state).to eq('ON')
        end
      end
    end
  else
    describe 'No DNS Zones found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have DNSSEC enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-83'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (zone:GCP_DNS_MANAGEDZONE)
    RETURN zone.name as name, zone.resource_data_dnssecConfig_state as state, zone.resource_data_dnssecConfig_defaultKeySpecs_0_keyType as first_type, zone.resource_data_dnssecConfig_defaultKeySpecs_0_algorithm as first_algorithm, zone.resource_data_dnssecConfig_defaultKeySpecs_1_keyType as second_type, zone.resource_data_dnssecConfig_defaultKeySpecs_1_algorithm as second_algorithm
  )
  zones = graphdb.query(q).mapped_results
  if zones.length > 0
    zones.each do |zone|
      zone_type = nil
      zone_algorithm = nil

      if zone.first_type == 'KEY_SIGNING'
        zone_type = zone.first_type
        zone_algorithm = zone.first_algorithm
      end
      if zone.second_type == 'KEY_SIGNING'
        zone_type = zone.second_type
        zone_algorithm = zone.second_algorithm
      end

      describe zone.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have RSASHA1 for the Key Signing Key' do
          expect(zone_algorithm).not_to eq('RSASHA1')
        end
      end
    end
  else
    describe 'No DNS Zones found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have RSASHA1 for the Signing Key' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-84'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (zone:GCP_DNS_MANAGEDZONE)
    RETURN zone.name as name, zone.resource_data_dnssecConfig_state as state, zone.resource_data_dnssecConfig_defaultKeySpecs_0_keyType as first_type, zone.resource_data_dnssecConfig_defaultKeySpecs_0_algorithm as first_algorithm, zone.resource_data_dnssecConfig_defaultKeySpecs_1_keyType as second_type, zone.resource_data_dnssecConfig_defaultKeySpecs_1_algorithm as second_algorithm
  )
  zones = graphdb.query(q).mapped_results
  if zones.length > 0
    zones.each do |zone|
      zone_type = nil
      zone_algorithm = nil

      if zone.first_type == 'ZONE_SIGNING'
        zone_type = zone.first_type
        zone_algorithm = zone.first_algorithm
      end
      if zone.second_type == 'ZONE_SIGNING'
        zone_type = zone.second_type
        zone_algorithm = zone.second_algorithm
      end

      describe zone.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have RSASHA1 for the Zone Signing Key' do
          expect(zone_algorithm).not_to eq('RSASHA1')
        end
      end
    end
  else
    describe 'No DNS Zones found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have RSASHA1 for the Signing Key' do
        expect(true).to eq(true)
      end
    end
  end
end

# TODO: GCP_COMPUTE_INSTANCE GCP_IDENTITY
control_id = 'darkbit-gcp-85'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-86'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (i:GCP_COMPUTE_INSTANCE)
    WHERE i.resource_data_labels_goog_gke_node IS NULL
    OPTIONAL MATCH (i:GCP_COMPUTE_INSTANCE)-[r:HAS_OAUTHSCOPE]->(s:GCP_IAM_OAUTHSCOPE { name: 'https://www.googleapis.com/auth/cloud-platform'} )
    WHERE i.resource_data_labels_goog_gke_node IS NULL
    RETURN i.name as name, s.name as cloud_platform_scope
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have cloud-platform oauth scope assigned' do
          expect(instance.cloud_platform_scope).to eq(nil)
        end
      end
    end
  else
    describe 'No Instances found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have cloud-platform oauth scope assigned' do
        expect(true).to eq(true)
      end
    end
  end
end

# BLOCKED: Parsing of metadata keys GCP_COMPUTE_INSTANCE
control_id = 'darkbit-gcp-87'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Parsing of metadata keys GCP_COMPUTE_INSTANCE
control_id = 'darkbit-gcp-88'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Parsing of metadata keys GCP_COMPUTE_INSTANCE
control_id = 'darkbit-gcp-89'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-90'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (i:GCP_COMPUTE_INSTANCE)
    WHERE i.resource_data_labels_goog_gke_node IS NULL
    RETURN i.name as name, i.resource_data_canIpForward as can_ip_forward
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not have ip forwarding enabled' do
          expect(instance.can_ip_forward).to eq('false')
        end
      end
    end
  else
    describe 'No Instances found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not have ip forwarding enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

# TODO: GCP_COMPUTE_INSTANCE and GCP_COMPUTE_DISK
control_id = 'darkbit-gcp-91'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-92'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH  (i:GCP_COMPUTE_INSTANCE)
    WHERE  i.resource_data_labels_goog_gke_node IS NULL
    RETURN i.name,
           i.resource_data_shieldedInstanceConfig_enableIntegrityMonitoring as integrity_monitoring,
           i.resource_data_shieldedInstanceConfig_enableSecureBoot as secure_boot,
           i.resource_data_shieldedInstanceConfig_enableVtpm as enable_vtpm
  )
  instances = graphdb.query(q).mapped_results
  if instances.length > 0
    instances.each do |instance|
      describe instance.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have shielded node configuration enabled' do
          expect(instance.integrity_monitoring).to eq('true')
          expect(instance.secure_boot).to eq('true')
          expect(instance.enable_vtpm).to eq('true')
        end
      end
    end
  else
    describe 'No Instances found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have shielded node configuration enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

# TODO: GCP_APPENGINE_APPLICATION
control_id = 'darkbit-gcp-93'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_STORAGE_BUCKET and IAM
control_id = 'darkbit-gcp-94'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_STORAGE_BUCKET
control_id = 'darkbit-gcp-95'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Needs CloudSQL deep parsing
control_id = 'darkbit-gcp-97'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Needs CloudSQL deep parsing
control_id = 'darkbit-gcp-98'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Needs CloudSQL deep parsing
control_id = 'darkbit-gcp-99'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Needs CloudSQL deep parsing
control_id = 'darkbit-gcp-100'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Needs CloudSQL deep parsing
control_id = 'darkbit-gcp-101'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Needs CloudSQL deep parsing
control_id = 'darkbit-gcp-102'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Needs CloudSQL deep parsing
control_id = 'darkbit-gcp-103'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Needs CloudSQL deep parsing
control_id = 'darkbit-gcp-104'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Needs CloudSQL deep parsing
control_id = 'darkbit-gcp-105'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Needs CloudSQL deep parsing
control_id = 'darkbit-gcp-106'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# BLOCKED: Needs CloudSQL deep parsing
control_id = 'darkbit-gcp-107'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_BIGQUERY_DATASET and IAM
control_id = 'darkbit-gcp-108'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_CONTAINER_CLUSTER
control_id = 'darkbit-gcp-109'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_SERVICEUSAGE_SERVICE and GCP_CONTAINERREGISTRY_IMAGE and GCP_STORAGE_BUCKET
control_id = 'darkbit-gcp-110'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

# TODO: GCP_CONTAINER_CLUSTER and IAM and GCP_SERVICEUSAGE_SERVICE and GCP_CONTAINERREGISTRY_IMAGE and GCP_STORAGE_BUCKET
control_id = 'darkbit-gcp-112'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-113'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_NODEPOOL)
    RETURN c.name as name, c.config_metadata_disable_legacy_endpoints as disabled_legacy_metadata
  )
  gkenodepools = graphdb.query(q).mapped_results
  if gkenodepools.length > 0
    gkenodepools.each do |nodepool|
      describe nodepool.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have legacy metadata endpoints disabled' do
          expect(nodepool.disabled_legacy_metadata).to eq('true')
        end
      end
    end
  else
    describe 'No GKE NodePools found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have legacy metadata endpoints disabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-114'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_releaseChannel_channel as channel_type
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should use stable or regular channel' do
          expect(cluster.channel_type).not_to eq('RAPID')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should use stable or regular channel' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-115'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_privateClusterConfig_enablePrivateNodes as private_nodes
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have private nodes configured' do
          expect(cluster.private_nodes).to eq('true')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have private nodes configured' do
        expect(true).to eq(true)
      end
    end
  end
end

# TODO: GCP_COMPUTE_TARGETHTTPSPROXY
control_id = 'darkbit-gcp-117'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-121'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_authenticatorGroupsConfig_enabled as google_groups_rbac
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have google groups RBAC integration configured' do
          expect(cluster.google_groups_rbac).to eq('true')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have google groups RBAC integration configured' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-122'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (instance:GCP_COMPUTE_INSTANCE)-[:HAS_DISK]->(disk:GCP_COMPUTE_DISK)
    WHERE NOT instance.resource_data_labels_goog_gke_node IS NULL
    RETURN instance.name, disk.resource_data_diskEncryptionKey_kmsKeyName as key_name
  )
  gkenodes = graphdb.query(q).mapped_results
  if gkenodes.length > 0
    gkenodes.each do |node|
      describe node.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have CMEK configured for its disks' do
          expect(node.key_name).not_to be_nil
        end
      end
    end
  else
    describe 'No GKE Node Instances found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have CMEK configured for its disks' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-123'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_enableKubernetesAlpha as alpha
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should not run alpha clusters' do
          expect(cluster.alpha).not_to eq('true')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should not run alpha clusters' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-124'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (np:GCP_CONTAINER_NODEPOOL)
    WHERE NOT np.name ENDS WITH '/default-pool'
    RETURN np.name, np.resource_data_config_sandboxConfig_sandboxType as sandbox_type
  )
  nps = graphdb.query(q).mapped_results
  if nps.length > 0
    nps.each do |np|
      describe np.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have Gvisor enabled' do
          expect(np.sandbox_type).to eq('GVISOR')
        end
      end
    end
  else
    describe 'No GKE Nodepools found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have Gvisor enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

control_id = 'darkbit-gcp-125'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  q = %s(
    MATCH (c:GCP_CONTAINER_CLUSTER)
    RETURN c.name as name, c.resource_data_binaryAuthorization_enabled as binary_authorization
  )
  gkeclusters = graphdb.query(q).mapped_results
  if gkeclusters.length > 0
    gkeclusters.each do |cluster|
      describe cluster.name, control_pack: control_pack, control_id: control_id, "#{control_id}": true do
        it 'should have binary authorization enabled' do
          expect(cluster.binary_authorization).to eq('true')
        end
      end
    end
  else
    describe 'No GKE Clusters found', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
      it 'should have binary authorization enabled' do
        expect(true).to eq(true)
      end
    end
  end
end

# BLOCKED: Ability to validate CSCC automatically?
control_id = 'darkbit-gcp-126'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end
