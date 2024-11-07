require "signet/oauth_2/client"
require "bing_ads_ruby_sdk/oauth2/fs_store"

module BingAdsRubySdk
  module OAuth2
    # Adds some useful methods to Signet::OAuth2::Client
    class AuthorizationHandler
      API_URLS = {
        sandbox: {
          scope: "https://api.ads.microsoft.com/msads.manage",
          authorize_uri: "https://login.windows-ppe.net/consumers/oauth2/v2.0/authorize",
          token_uri: "https://login.windows-ppe.net/consumers/oauth2/v2.0/token"
        },
        production: {
          scope: "https://ads.microsoft.com/msads.manage",
          authorize_uri: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
          token_uri: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
          redirect_uri: "https://login.microsoftonline.com/common/oauth2/nativeclient"
        }
      }.freeze

      # @param developer_token
      # @param client_id
      # @param store [Store]
      # @param environment [environment]
      def initialize(developer_token:, client_id:, store:, client_secret: nil, environment: :production, redirect_uri: nil)
        @environment = environment
        @redirect_uri = redirect_uri
        @client = Signet::OAuth2::Client.new(
          client_params(developer_token, client_id, client_secret)
        )
        @store = store
      end

      # @return [String] unless client.client_id url is nil interpolated url.
      # @return [nil] if client.client_id is nil.
      def code_url
        return nil if client.client_id.nil?
        "#{authorize_uri}?client_id=#{client.client_id}&" \
        "scope=offline_access+#{scope}&response_type=code&" \
        "redirect_uri=#{redirect_uri}"
      end

      # Once you have completed the oauth process in your browser using the code_url
      # copy the url your browser has been redirected to and use it as argument here
      def fetch_from_url(url)
        codes = extract_codes(url)

        return false if codes.none?
        fetch_from_code(codes.last)
      end

      # Get or fetch an access token.
      # @return [String] The access token.
      def fetch_or_refresh
        refresh_from_store
        fetch_and_write if client.expired?
        client.access_token
      end

      private

      attr_reader :client, :store, :environment

      # Refresh existing authorization token
      # @return [Signet::OAuth2::Client] if everything went well.
      # raises error if the token can't be read from the store.
      def refresh_from_store
        ext_token = store.read
        raise "Cannot refresh token : Unable to read store data" if !ext_token&.is_a?(Hash) || ext_token.empty?
        client.update_token!(ext_token)
      end

      # Request the Api to exchange the code for the access token.
      # Save the access token through the store.
      # @param [String] code authorization code from bing's ads.
      # @return [#store.write] store's write output.
      def fetch_from_code(code)
        client.code = code
        fetch_and_write
      end

      def fetch_and_write
        client.fetch_access_token!(scope: scope)
        store.write(token_data)
      end

      def extract_codes(url)
        url = URI.parse(url)
        query_params = URI.decode_www_form(url.query)
        query_params.find { |arg| arg.first.casecmp("CODE").zero? }
      end

      def client_params(developer_token, client_id, client_secret)
        {
          authorization_uri: authorize_uri,
          token_credential_uri: token_uri,
          redirect_uri: redirect_uri,
          developer_token: developer_token,
          client_id: client_id
        }.tap do |hash|
          hash[:client_secret] = client_secret if client_secret
        end
      end

      def token_data
        {
          access_token: client.access_token,
          refresh_token: client.refresh_token,
          issued_at: client.issued_at,
          expires_in: client.expires_in
        }
      end

      def authorize_uri
        API_URLS[environment][:authorize_uri]
      end

      def scope
        API_URLS[environment][:scope]
      end

      def token_uri
        API_URLS[environment][:token_uri]
      end

      def redirect_uri
        raise "Redirect URI not defined for Sandbox" if environment == :sandbox && @redirect_uri.nil?

        return @redirect_uri if environment == :sandbox

        API_URLS[environment][:redirect_uri]
      end
    end
  end
end
