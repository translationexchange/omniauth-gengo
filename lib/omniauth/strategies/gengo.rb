require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Gengo < OmniAuth::Strategies::OAuth2

      option :client_options, {
        :site           => 'https://api.gengo.com/v2',
        :authorize_url  => 'https://gengo.com/oauth/authorize',
        :token_url      => 'https://api.gengo.com/v2/oauth/token'
      }

      option :name, 'gengo'

      option :access_token_options, {
        :header_format => 'OAuth %s',
        :param_name => 'access_token'
      }
      
      option :authorize_options, [:scope, :display]

      def request_phase
        super
      end

      uid { raw_info['id'] }
      
      info do
        prune!({
          'id'             => raw_info['id'],
          'name'           => raw_info['name'],
          'first_name'     => raw_info['first_name'],
          'last_name'      => raw_info['last_name'],
          'email'          => raw_info['email'],
          'gender'         => raw_info['gender'],
          'mugshot'        => raw_info['mugshot']
        })
      end
      
      extra do 
        { 'user' =>  prune!(raw_info) }
      end
      
      def raw_info
        @raw_info ||= access_token.get('/account').parsed
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
