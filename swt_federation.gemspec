# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "swt_federation/version"

Gem::Specification.new do |s|
  s.name        = "swt_federation"
  s.version     = SwtFederation::VERSION
  s.authors     = ["NicoPaez"]
  s.email       = ["nicopaez@gmail.com"]
  s.homepage    = ""
  s.summary     = %q{This gem provides website federation based on Simple Web Tokens (SWT)}
  s.description = %q{It is inspired on this post (http://blogs.msdn.com/b/silverlining/archive/2011/10/03/ruby-web-sites-and-windows-azure-appfabric-access-control.aspx) by Larry Franks.}

  s.rubyforge_project = "swt_federation"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  #s.require_paths = ["lib"]

  # specify any dependencies here; for example:
  # s.add_development_dependency "rspec"
  # s.add_runtime_dependency "rest-client"
  s.add_dependency "nokogiri"

end
