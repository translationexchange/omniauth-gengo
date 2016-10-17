require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Gengo < OmniAuth::Strategies::OAuth2

      option :client_options, {
          :site => 'https://api.gengo.com/v2',
          :authorize_url => 'https://gengo.com/oauth/authenticate',
          :token_url => 'https://api.gengo.com/oauth/token'
      }
      option :name, 'gengo'

      option :access_token_options, {
          :header_format => 'OAuth %s',
          :param_name => 'access_token'
      }

      option :authorize_options, [:scope, :display]

      # # TODO: deal with situations when client declines the authorization
      #
      # # All this because Gengo does not return token in a standard form
      # def build_access_token
      #   params = {
      #       :client_id => options.client_id,
      #       :client_secret => options['secret_key']
      #   }.merge(token_params.to_hash(:symbolize_keys => true))
      #
      #   params = {'grant_type' => 'authorization_code', 'auth_code' => request.params['code']}.merge(params)
      #   access_token_opts = deep_symbolize(options.auth_token_params)
      #
      #   opts = {:raise_errors => false, :parse => params.delete(:parse)}
      #   if client.options[:token_method] == :post
      #     headers = params.delete(:headers)
      #     opts[:body] = params
      #     opts[:headers] =  {'Content-Type' => 'application/x-www-form-urlencoded'}
      #     opts[:headers].merge!(headers) if headers
      #   else
      #     opts[:params] = params
      #   end
      #
      #   response = client.request(client.options[:token_method], client.token_url, opts)
      #   data = {
      #       'access_token' => response.parsed['results']['access_token'],
      #       'expires_in' => response.parsed['results']['expires'],
      #   }
      #
      #   ::OAuth2::AccessToken.from_hash(client, data.merge(access_token_opts))
      # end


      uid { raw_info['id'] }

      info do
        prune!({
                   'email' => raw_info['email'],
                   'full_name' => raw_info['full_name'],
                   'display_name' => raw_info['display_name'],
                   'language_code' => raw_info['language_code']
               })
      end

      extra do
        {'user' => prune!(raw_info)}
      end

      def raw_info
        @raw_info ||= access_token.get('/account/me').parsed
      end

      def authorize_params
        super.tap do |params|
          params.merge!(:display => request.params['display']) if request.params['display']
          params.merge!(:state => request.params['state']) if request.params['state']
        end
      end

      private

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end

    end
  end
end

OmniAuth.config.add_camelization 'gengo', 'Gengo'
