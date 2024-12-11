# Certificate trees generated:
#
# 4. Core Trust Framework Signing CA
#     5. Core Trust Framework Signing Issuer
#          ... organisation certificates
#
# Use EC keys, with the P-256 curve used in JWS.

set -e

if ! which openssl
then
    echo "openssl must be in your PATH" >&2
    exit 1
fi

# 4. Core Trust Framework Signing CA
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 4-signing-ca-key.pem
openssl req -new -key 4-signing-ca-key.pem -out 4-signing-ca-csr.pem \
    -subj "/C=GB/O=Core Trust Framework/CN=Core Trust Framework Signing CA"
openssl x509 -req -in 4-signing-ca-csr.pem -out 4-signing-ca-cert.pem -extfile ../scripts/extensions.cnf \
    -extensions v3_ca -key 4-signing-ca-key.pem -days 3650

# 5. Core Trust Framework Signing Issuer
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 5-signing-issuer-key.pem
openssl req -new -key 5-signing-issuer-key.pem -out 5-signing-issuer-csr.pem \
    -subj "/C=GB/ST=London/O=Core Trust Framework/CN=Core Trust Framework Signing Issuer"
openssl x509 -req -in 5-signing-issuer-csr.pem -out 5-signing-issuer-ca.pem -extfile ../scripts/extensions.cnf \
    -extensions v3_intermediate_ca -CA 4-signing-ca-cert.pem -CAkey 4-signing-ca-key.pem -days 365

# ---------------------------------------------------------------------------

# 6. Industrial Metering Company (role: energy-data-provider)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 6-industrial-metering-company-key.pem
openssl req -new -key 6-industrial-metering-company-key.pem -out 6-industrial-metering-company-csr.pem \
    -subj "/C=GB/ST=London/O=Industrial Metering Company/CN=https:\/\/directory.core.trust.ib1.org\/member\/237256"
openssl x509 -req -in 6-industrial-metering-company-csr.pem -out 6-industrial-metering-company-cert.pem -extfile ../scripts/roles.cnf -extensions roles6 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365
cat 6-industrial-metering-company-cert.pem 5-signing-issuer-ca.pem > 6-industrial-metering-company-cert-bundle.pem

# 7. Nitrogen Fertiliser Products (role: supplier)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 7-nitrogen-fertiliser-products-key.pem
openssl req -new -key 7-nitrogen-fertiliser-products-key.pem -out 7-nitrogen-fertiliser-products-csr.pem \
    -subj "/C=GB/ST=London/O=Nitrogen Fertiliser Products/CN=https:\/\/directory.core.trust.ib1.org\/member\/293482"
openssl x509 -req -in 7-nitrogen-fertiliser-products-csr.pem -out 7-nitrogen-fertiliser-products-cert.pem -extfile ../scripts/roles.cnf -extensions roles7 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365
cat 7-nitrogen-fertiliser-products-cert.pem 5-signing-issuer-ca.pem > 7-nitrogen-fertiliser-products-cert-bundle.pem

# 8. Agricultural Wholesale Supplies (role: distributor)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 8-agricultural-wholesale-supplies-key.pem
openssl req -new -key 8-agricultural-wholesale-supplies-key.pem -out 8-agricultural-wholesale-supplies-csr.pem \
    -subj "/C=GB/ST=London/O=Agricultural Wholesale Supplies/CN=https:\/\/directory.core.trust.ib1.org\/member\/927625"
openssl x509 -req -in 8-agricultural-wholesale-supplies-csr.pem -out 8-agricultural-wholesale-supplies-cert.pem -extfile ../scripts/roles.cnf -extensions roles8 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365
cat 8-agricultural-wholesale-supplies-cert.pem 5-signing-issuer-ca.pem > 8-agricultural-wholesale-supplies-cert-bundle.pem

# 9. Precise Farm Automation Co (role: farm-management-provider)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 9-precise-farm-automation-co-key.pem
openssl req -new -key 9-precise-farm-automation-co-key.pem -out 9-precise-farm-automation-co-csr.pem \
    -subj "/C=GB/ST=London/O=Precise Farm Automation Co/CN=https:\/\/directory.core.trust.ib1.org\/member\/143252"
openssl x509 -req -in 9-precise-farm-automation-co-csr.pem -out 9-precise-farm-automation-co-cert.pem -extfile ../scripts/roles.cnf -extensions roles9 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365
cat 9-precise-farm-automation-co-cert.pem 5-signing-issuer-ca.pem > 9-precise-farm-automation-co-cert-bundle.pem

# 10. High Street Bank (role: financial-service-provider)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 10-high-street-bank-key.pem
openssl req -new -key 10-high-street-bank-key.pem -out 10-high-street-bank-csr.pem \
    -subj "/C=GB/ST=London/O=High Street Bank/CN=https:\/\/directory.core.trust.ib1.org\/member\/725245"
openssl x509 -req -in 10-high-street-bank-csr.pem -out 10-high-street-bank-cert.pem -extfile ../scripts/roles.cnf -extensions roles10 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365
cat 10-high-street-bank-cert.pem 5-signing-issuer-ca.pem > 10-high-street-bank-cert-bundle.pem

# 11. Rosemary Accountancy Software (role: accounts-platform-provider)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 11-rosemary-accountancy-software-key.pem
openssl req -new -key 11-rosemary-accountancy-software-key.pem -out 11-rosemary-accountancy-software-csr.pem \
    -subj "/C=GB/ST=London/O=Rosemary Accountancy Software/CN=https:\/\/directory.core.trust.ib1.org\/member\/394722"
openssl x509 -req -in 11-rosemary-accountancy-software-csr.pem -out 11-rosemary-accountancy-software-cert.pem -extfile ../scripts/roles.cnf -extensions roles11 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365
cat 11-rosemary-accountancy-software-cert.pem 5-signing-issuer-ca.pem > 11-rosemary-accountancy-software-cert-bundle.pem

# 12. Sustainable Farm Systems (role: environmental-reporting-provider)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 12-sustainable-farm-systems-key.pem
openssl req -new -key 12-sustainable-farm-systems-key.pem -out 12-sustainable-farm-systems-csr.pem \
    -subj "/C=GB/ST=London/O=Sustainable Farm Systems/CN=https:\/\/directory.core.trust.ib1.org\/member\/183426"
openssl x509 -req -in 12-sustainable-farm-systems-csr.pem -out 12-sustainable-farm-systems-cert.pem -extfile ../scripts/roles.cnf -extensions roles12 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365
cat 12-sustainable-farm-systems-cert.pem 5-signing-issuer-ca.pem > 12-sustainable-farm-systems-cert-bundle.pem

# 13. Green Bank of London (role: financial-service-provider)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out 13-green-bank-of-london-key.pem
openssl req -new -key 13-green-bank-of-london-key.pem -out 13-green-bank-of-london-csr.pem \
    -subj "/C=GB/ST=London/O=Green Bank of London/CN=https:\/\/directory.core.trust.ib1.org\/member\/582373"
openssl x509 -req -in 13-green-bank-of-london-csr.pem -out 13-green-bank-of-london-cert.pem -extfile ../scripts/roles.cnf -extensions roles13 \
    -CA 5-signing-issuer-ca.pem -CAkey 5-signing-issuer-key.pem -days 365
cat 13-green-bank-of-london-cert.pem 5-signing-issuer-ca.pem > 13-green-bank-of-london-cert-bundle.pem

