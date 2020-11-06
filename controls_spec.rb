require 'yaml'

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

# TODO: map relationship to account and check across accounts
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
    RETURN c.name AS name, l.enabled AS logging_enabled, t.name AS logging_type
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
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

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
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-18'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-19'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

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
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-23'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-26'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

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
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-39'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
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
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-44'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-47'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-48'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-50'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-52'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-53'
RSpec.describe "[#{control_id}] #{titles[control_id]}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
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
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-59'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-60'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
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
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-62'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-63'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-64'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-65'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-66'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-67'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-72'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-73'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-74'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-75'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-76'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-77'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-78'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-79'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-80'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-81'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-82'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-83'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-84'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-85'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-86'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-87'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-88'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-89'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-90'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-91'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-92'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-93'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-94'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-95'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-97'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-98'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-99'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-100'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-101'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-102'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-103'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-104'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-105'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-106'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-107'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-108'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-109'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-110'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-112'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-113'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-114'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-115'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-117'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-121'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-122'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-123'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-124'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-125'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end

control_id = 'darkbit-gcp-126'
title = config_file['controls'].filter { |control| control['id'] == control_id }.first['title'] || 'Unknown Title'
RSpec.describe "[#{control_id}] #{title}" do
  describe 'Placeholder', control_pack: control_pack, control_id: control_id, "#{control_id}": true do
    it 'should not have a placeholder configuration' do
      expect(true).to eq(true)
    end
  end
end
