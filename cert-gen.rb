
roles = ''
signers = ''
number = 6

[
  ['237256', 'Industrial Metering Company', 'energy-data-provider'],
  ['293482', 'Nitrogen Fertiliser Products', 'supplier'],
  ['927625', 'Agricultural Wholesale Supplies', 'distributor'],
  ['143252', 'Precise Farm Automation Co', 'farm-management-provider'],
  ['394722', 'Rosemary Accountancy Software', 'accounts-platform-provider'],
  ['183426', 'Sustainable Farm Systems', 'environmental-reporting-provider'],
  ['582373', 'Green Bank of London', 'financial-service-provider']
].each do |id, name, role|

  symbol = name.downcase.gsub(' ','-')
  print <<__E
# #{number}. #{name} (role: #{role})
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out #{number}-#{symbol}-key.pem
openssl req -new -key #{number}-#{symbol}-key.pem -out #{number}-#{symbol}-csr.pem \\
    -subj "/C=GB/ST=London/O=#{name}/CN=https:\\/\\/directory.core.trust.ib1.org\\/member\\/#{id}"
openssl x509 -req -in #{number}-#{symbol}-csr.pem -out #{number}-#{symbol}-cert.pem -extfile ../scripts/roles.cnf -extensions roles#{number} \\
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365
cat #{number}-#{symbol}-cert.pem 5-signing-issuer-ca.pem > #{number}-#{symbol}-cert-bundle.pem

__E

  roles << <<__E
[roles#{number}]
subjectAltName = URI:https://directory.core.trust.ib1.org/member/#{id}
1.3.6.1.4.1.62329.1.1=ASN1:SEQUENCE:role_values#{number}
1.3.6.1.4.1.62329.1.2=ASN1:UTF8:https://directory.core.trust.ib1.org/scheme/supply/application/#{id.to_i*7}

[role_values#{number}]
value.1=UTF8:https://registry.core.trust.ib1.org/scheme/supply/role/#{role}

# ---------------------------------------------------------------------------

__E

  signers << "\"#{number}-#{symbol}\",\n"

  number += 1

end

print roles
print signers
