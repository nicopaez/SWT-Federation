require 'rspec'
require 'simplecov'

SimpleCov.start do
  root(File.join(File.dirname(__FILE__), '../'))
  add_filter '/specs/'
end

