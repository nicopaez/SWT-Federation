require 'rspec'
require 'simplecov'

SimpleCov.start do
  root(File.join(File.dirname(__FILE__), '../'))
  coverage_dir 'build/coverage'
  add_filter '/specs/'
  add_filter '/build/'
end

RSpec.configure do |config|
  config.add_formatter('documentation')
end

