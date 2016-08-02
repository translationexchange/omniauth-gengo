# -*- encoding: utf-8 -*-
$:.push File.expand_path('../lib', __FILE__)
require 'omniauth/gengo/version'

Gem::Specification.new do |s|
  s.name     = 'omniauth-gengo'
  s.version  = OmniAuth::Gengo::VERSION
  s.authors  = ['Michael Berkovich']
  s.email    = ['michael@translationexchange.com']
  s.summary  = 'Gengo strategy for OmniAuth'
  s.homepage = 'https://github.com/translationexchange/omniauth-gengo'

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  s.require_paths = ['lib']

  s.add_runtime_dependency 'omniauth-oauth2', '~> 1.1'

  s.add_development_dependency 'rspec', '~> 2.7.0'
  s.add_development_dependency 'rake'
end
