require "bundler/gem_tasks"
require 'rspec/core/rake_task'

desc "Run specs"
task :spec do
  RSpec::Core::RakeTask.new(:spec) do |t|
    t.rspec_opts = ['--format RspecJunitFormatter', '--out build/rspec.xml']
    t.pattern = './spec/*_spec.rb'
  end
end


task :default => :spec
