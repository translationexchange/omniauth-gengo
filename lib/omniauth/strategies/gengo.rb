require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Gengo < OmniAuth::Strategies::OAuth2

      option :client_options, {
          :site => 'https://api.gengo.com/v2',
          :authorize_url => 'https://gengo.com/oauth/authenticate',
          :token_url => 'https://gengo.com/oauth/token'
      }
      option :name, 'gengo'

      option :access_token_options, {
          :header_format => 'Bearer %s',
          :param_name => 'access_token'
      }

      option :authorize_options, [:scope, :display]

      uid { raw_info['email'] }

      info do
        prune!(
            'email' => raw_info['response']['email'],
            'full_name' => raw_info['response']['full_name'],
            'display_name' => raw_info['response']['display_name'],
            'language_code' => raw_info['response']['language_code']
        )
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
