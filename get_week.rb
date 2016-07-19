#!/home/clem/.rbenv/shims/ruby

require 'date'
require 'pp'
require 'rubygems'
require 'to_regexp'
require 'mongo'
require 'optparse'
require 'ostruct'
require 'restclient'
require 'axlsx'
#require 'pry'

$releases=['wheezy','jessie']
$global = {}

# parse debsec base, searching for packages impacted by cve
def find_debian_patch(debsec,cve)
  references = cve[:references].join("\x0D\x0A")
  packages={cve["id"] => {"packages" => {}, "description" => cve["summary"], "cvss" => cve["cvss"].to_s, "published" => cve["Published"][0,10], "modified" => cve["Modified"][0,10], "references" => references } }
  debsec.keys.each do |k|
    if (not debsec[k][cve["id"]].nil?)
      $releases.each do |release|
	if (not debsec[k][cve["id"]]['releases'][release].nil?) 
	  packages[cve["id"]]["packages"].merge!( k => debsec[k][cve["id"]]['releases'].select {|p| $releases.include?p } )
	end
      end
    end
  end
  return packages
end

def create_excel
  $global["excel"] = Axlsx::Package.new
end

def write_excel 
  $global["excel"].serialize $options.excel
end

def output_cve_to_excel(c)
  $global["excel"].workbook do |wb|
    styles = wb.styles
    header = styles.add_style :bg_color => '00', :fg_color => 'FF', :b => true
    default = styles.add_style alignment: { wrap_text: true,:horizontal => :left, :vertical => :top }, height: 10

    wb.add_worksheet(:name => 'Divers') do  |ws|
      ws.add_row ['CVE', 'Product', 'CVSS Score','Published','Modified','Description','References'], :style => header
      c.each do |cve|
	next if cve[:summary] =~ /^\*\* REJECT \*\*  DO NOT USE THIS CANDIDATE NUMBER/
	next if cve[:summary] =~ /^\*\* DISPUTED \*\*/
	vuln_product = cve[:vulnerable_configuration].map {|m| m.split(':')[3..4].join(' / ') }.uniq.join("\x0D\x0A")
	references = cve[:references].join("\x0D\x0A")
	ws.add_row [ cve["id"], vuln_product, cve["cvss"],cve[:Published][0,10],cve[:Modified][0,10], cve["summary"],references ], :style => default
      end
      ws.column_widths 15,30,15,15,15,60,40
    end
  end
end


def output_debian_to_excel(packages)

  $global["excel"].workbook do |wb|
    styles = wb.styles
    default = styles.add_style alignment: { wrap_text: true,:horizontal => :left, :vertical => :top }, height: 10
    header = styles.add_style :bg_color => '00', :fg_color => 'FF', :b => true

    wb.add_worksheet(:name => 'Debian') do  |ws|
      ws.add_row ['CVE', 'CVSS', 'Package', 'Release','Status','Fixed versions','Published','Modified','Description', 'References'], :style => header
      packages.each do |cve,infos|
	infos['packages'].each do |pkg,rels|
	  rels.each do |rel, stat|
	    if (stat['status'] == "resolved" and stat['fixed_version'] == "0")
	      status = "not affected"
	    else
	      status = stat['status']
	    end
	    ws.add_row [ cve, infos['cvss'], pkg, rel, status, stat['fixed_version'],infos['published'], infos['modified'], infos['description'], infos['references'] ]
	  end
	end
      end
      ws.column_widths 20,10,20,20,20,15,15,20,40,20
    end
  end



end

def list_debian_patchs(c)
  r=RestClient.get("https://security-tracker.debian.org/tracker/data/json")
  #r=File.read('json')
  h=JSON.parse(r)
  packages={}
  c.each do |cve|
    next if cve[:summary] =~ /^\*\* REJECT \*\*  DO NOT USE THIS CANDIDATE NUMBER/
    next if cve[:summary] =~ /^\*\* DISPUTED \*\*/
    puts "[ %s / CVSS %s / published : %s / modified : %s ]" % [cve[:id],cve[:cvss],cve[:Published][0,10],cve[:Modified][0,10] ]
    if ($options.quiet.nil?)
      puts "\t[Summary :]\n%s" % [cve[:summary]]
      puts "\t[References :]"
      cve[:references].each do |ref|
	puts "\t"+ref
      end

      vulnconfs = cve[:vulnerable_configuration].map {|m| m.split(':')[3..4].join(' / ') }.uniq
      puts "\t[ vulnconfs ]"
      vulnconfs.each do |vc|
	puts "\t"+vc
      end
      puts "\t[ deb patchs ]"
      #pp packages
    end
    packages.merge!(find_debian_patch(h,cve))
  end
  #binding.pry
  output_debian_to_excel(packages)

end

$options = OpenStruct.new
OptionParser.new do |opt|
  opt.on('-y', '--year YYYY', 'Year number') { |o| $options.year = o }
  opt.on('-w', '--week W', 'Week number') { |o| $options.week = o }
  opt.on('-c', '--cpe CPE,CPE', 'CPE (regex match)') { |o| $options.cpe= o }
  opt.on('-C', '--cve CVE,CVE', 'CVE (regex match)') { |o| $options.cve= o }
  opt.on('-f', '--from YYYY-MM-DD', 'From date') { |o| $options.from= o }
  opt.on('-t', '--to CYYYY-MM-DD', 'To date') { |o| $options.to = o }
  opt.on('-q', '--quiet', 'Quiet mode (only print CVE number)') { $options.quiet= true }
  opt.on('-x', '--excel FILENAME', 'Excel weekly output mode') { |o| $options.excel = o }
end.parse!


Mongo::Logger.logger.level = ::Logger::FATAL

url='mongodb://u-dev:27017/cvedb'

if (not $options.year.nil? or not $options.week.nil?)
  if ($options.year.nil? or $options.week.nil?)
    puts "You must specify year AND week"
    exit
  end
end

if (not $options.from.nil? or not $options.to.nil?)
  if ($options.from.nil? or $options.to.nil?)
    puts "You must specify from AND to"
    exit
  end
end

find_opts = {}

if (not $options.from.nil?)
  from=DateTime.parse($options.from)
  to=DateTime.parse($options.to)
  ind_opts.merge!(Published: {'$gt' => from.to_s, '$lt' => to.to_s})
  #find_opts.merge!('$or' => [ { Published: {'$gt' => from.to_s, '$lt' => to.to_s} }, { Modified: {'$gt' => from.to_s, '$lt' => to.to_s } } ] )
end

if (not $options.year.nil?)
  from=Date.commercial($options.year.to_i,$options.week.to_i)
  to=from+7
  find_opts.merge!(Published: {'$gt' => from.to_s, '$lt' => to.to_s})
  #find_opts.merge!('$or' => [ { Published: {'$gt' => from.to_s, '$lt' => to.to_s} }, { Modified: {'$gt' => from.to_s, '$lt' => to.to_s } } ] )
end

if (not $options.cpe.nil?)
  cpe_search=$options.cpe.split(',')
  cpe_search_re = cpe_search.map {|c| ("/%s/" % [c] ).to_regexp }
  find_opts.merge!(vulnerable_configuration: {"$in" => cpe_search_re })
end

if (not $options.cve.nil?)
  cve_search=$options.cve.split(',')
  cve_search_re = cve_search.map {|c| ("/%s/" % [c] ).to_regexp }
  find_opts.merge!(id: {"$in" => cve_search_re })
end


puts "CVEs from %s to %s" % [from,to]
puts "Matching %s" % [$options.cpe] unless $options.cpe.nil?


mc=Mongo::Client.new(url)
cves=mc[:cves]
cpes=mc[:cpes]
puts find_opts

c_matching=cves.find(find_opts)

create_excel()

if (not $options.excel.nil?)
  list_debian_patchs(c_matching)
end

output_cve_to_excel(c_matching)

write_excel()

exit unless $options.quiet.nil?

c_matching.each do |cve|
  next if cve[:summary] =~ /^\*\* REJECT \*\*  DO NOT USE THIS CANDIDATE NUMBER/
  puts "[ %s / CVSS %s / published : %s / modified : %s ]" % [cve[:id],cve[:cvss],cve[:Published][0,10],cve[:Modified][0,10] ]
  if ($options.quiet.nil?)
    puts "\t[Summary :]\n%s" % [cve[:summary]]
    puts "\t[References :]"
    cve[:references].each do |ref|
      puts "\t"+ref
    end
    puts "\t[Vulnerable :]"
    cve[:vulnerable_configuration].each do |vuln|
      puts "\t"+vuln
    end
  end

end




