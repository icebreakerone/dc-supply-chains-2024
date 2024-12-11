import json

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ib1.provenance import Record
from ib1.provenance.signing import SignerFiles, SignerInMemory
from ib1.provenance.certificates import (
    CertificatesProviderSelfContainedRecord,
    CertificatesProviderLocal,
)


TRUST_FRAMEWORK_URL = "https://registry.core.trust.ib1.org/trust-framework"


if __name__ == "__main__":
    # Create a mechanism to provide certificates for verification. Multiple
    # implementations: embed certificates in record, entirely local, fetch from
    # Directory with local caching, etc.
    # Implements certificate policy, including whether certificates are included
    # in the record.
    # Provides the signing CA root certificate. Each environment will have its own
    # root CA.
    # Use certificates from the record, with policy to include them when adding steps
    certificate_provider = CertificatesProviderSelfContainedRecord(
        "certs/4-signing-ca-cert.pem"
    )

    # Create signers representing two applications to illustrate a record
    # passed between two members. (In a real application, you'd only have one.)
    # A few signer classes should be provided, eg local PEM files like this one,
    # or a key stored in AWS' key service.
    # Uses a Certificate Provider object for access to certificate policy.
    # Energy Data Provider Signer with certificates and key stored in files:

    signers = {}
    signer_file_list = [
        "6-industrial-metering-company",
        "7-nitrogen-fertiliser-products",
        "8-agricultural-wholesale-supplies",
        "9-precise-farm-automation-co",
        "10-high-street-bank",
        "11-rosemary-accountancy-software",
        "12-sustainable-farm-systems",
        "13-green-bank-of-london"
    ]
    for n in signer_file_list:
        signers[n] = SignerFiles(
                certificate_provider,
                "certs/"+n+"-cert-bundle.pem",
                "certs/"+n+"-key.pem"
            )
    signer_edp = signers['6-industrial-metering-company']
    signer_cap = signers['12-sustainable-farm-systems']
    signer_bank = signers['13-green-bank-of-london']

    # -----------------------------------------------------------------------
    # ===== EDP starts a new Record, fetching Smart Meter data
    edp_record = Record(TRUST_FRAMEWORK_URL)
    # - Permission step to record consent by end user
    edp_permission_id = edp_record.add_step(
        {
            "type": "permission",
            "scheme": "https://registry.core.trust.ib1.org/scheme/perseus",
            "timestamp": "2024-09-20T12:16:11Z",    # granted in past; must match audit trail
            "account": "/yl4Y/aV6b80fo5cnmuDDByfuEA=",
            "allows": {
                "licences": [
                    "https://smartenergycodecompany.co.uk/documents/sec/consolidated-sec/",
                    "https://registry.core.trust.ib1.org/scheme/perseus/licence/energy-consumption-data/2024-12-05"
                ]
            },
            "expires": "2025-09-20T12:16:11Z"       # 1 year
        }
    )
    # - Origin step for the smart meter data
    origin_id = edp_record.add_step(
        {
            "type": "origin",
            "scheme": "https://registry.core.trust.ib1.org/scheme/perseus",
            "sourceType": "https://registry.core.trust.ib1.org/scheme/perseus/source-type/Meter",
            "origin": "https://www.smartdcc.co.uk/",
            "originLicence": "https://smartenergycodecompany.co.uk/documents/sec/consolidated-sec/",
            "external": True,
            "permissions": [edp_permission_id],
            "perseus:scheme": {
                "meteringPeriod": {
                    "from": "2023-09-01Z",
                    "to": "2024-09-01Z"
                }
            },
            "perseus:assurance": {
                "missingData": "https://registry.core.trust.ib1.org/scheme/perseus/assurance/missing-data/Missing",
                "originMethod": "https://registry.core.trust.ib1.org/scheme/perseus/assurance/origin-method/SmartDCCOtherUser"
            }
        }
    )
    # - Transfer step to send it to the CAP
    edp_record.add_step(
        {
            "type": "transfer",
            "scheme": "https://registry.core.trust.ib1.org/scheme/perseus",
            "of": origin_id,
            "to": "https://directory.core.trust.ib1.org/member/81524", # CAP
            "standard": "https://registry.core.trust.ib1.org/scheme/perseus/standard/energy-consumption-data/2024-12-05",
            "licence": "https://registry.core.trust.ib1.org/scheme/perseus/licence/energy-consumption-data/2024-12-05",
            "service": "https://api.honestdave.example.com/meter-readings/0",
            "path": "/readings",
            "parameters": {
                "measure": "import",
                "from": "2023-09-01Z",
                "to": "2024-09-01Z"
            },
            "permissions": [edp_permission_id],
            "transaction": "C25D0B85-B7C4-4543-B058-7DA57B8D9A24",
        }
    )
    # EDP signs the steps
    edp_record_signed = edp_record.sign(signer_edp)
    # Get encoded data for inclusion in data response
    edp_data_attachment = edp_record_signed.encoded()

    # -----------------------------------------------------------------------
    # ===== CAP retrieves the data from the EDP, who includes a provenance record in the response
    cap_record = Record(TRUST_FRAMEWORK_URL, edp_data_attachment)
    # - Verify the signatures on the record
    cap_record.verify(certificate_provider)
    # - Find the transfer step, passing in the expected values for the transfer step (exceptions if not found)
    transfer_from_edp_step = cap_record.find_step(
        {
            # Same values as the transfer step added by the EDP
            "type": "transfer",
            "scheme": "https://registry.core.trust.ib1.org/scheme/perseus",
            "to": "https://directory.core.trust.ib1.org/member/81524", # CAP
            "standard": "https://registry.core.trust.ib1.org/scheme/perseus/standard/energy-consumption-data/2024-12-05",
            "licence": "https://registry.core.trust.ib1.org/scheme/perseus/licence/energy-consumption-data/2024-12-05",
            "service": "https://api.honestdave.example.com/meter-readings/0",
            "path": "/readings",
            "parameters": {
                "measure": "import",
                "from": "2023-09-01Z",
                "to": "2024-09-01Z"
            }
        }
    )
    # - Add a receipt step
    cap_receipt_id = cap_record.add_step(
        {
            "type": "receipt",
            "transfer": transfer_from_edp_step["id"]
        }
    )
    # - Permission step to record consent to processing and future transfer
    cap_permission_id = cap_record.add_step(
        {
            "type": "permission",
            "scheme": "https://registry.core.trust.ib1.org/scheme/perseus",
            "timestamp": "2024-10-21T09:09:10Z",    # granted in past; must match audit trail
            "account": "dbd16978-a0a642d9aa2d95318b50e605", # different to EDP as this is the CAP's account
            "allows": {
                "licences": [
                    "https://registry.core.trust.ib1.org/scheme/perseus/licence/emissions-report/2024-12-05"
                ],
                "processes": [
                    "https://registry.core.trust.ib1.org/scheme/perseus/process/emissions-calculations/2024-12-05"
                ]
            },
            "expires": "2025-10-21T09:09:10Z"       # 1 year
        }
    )
    # - Add an origin step for grid intensity data
    cap_intensity_origin_id = cap_record.add_step(
        {
            "type": "origin",
            "scheme": "https://registry.core.trust.ib1.org/scheme/perseus",
            "sourceType": "https://registry.core.trust.ib1.org/scheme/perseus/source-type/GridCarbonIntensity",
            "origin": "https://api.carbonintensity.org.uk/",
            "originLicence": "https://creativecommons.org/licenses/by/4.0/",
            "external": True,
            "perseus:scheme": {
                "meteringPeriod": {
                    "from": "2023-09-01Z",
                    "to": "2024-09-01Z"
                },
                "postcode": "CF99"
            },
            "perseus:assurance": {
                "missingData": "https://registry.core.trust.ib1.org/scheme/perseus/assurance/missing-data/Complete"
            }
        }
    )
    # - Add a process step to combine the data from the EDP and the grid intensity API into the report
    cap_processing_id = cap_record.add_step(
        {
            "type": "process",
            "scheme": "https://registry.core.trust.ib1.org/scheme/perseus",
            "inputs": [
                cap_receipt_id,
                cap_intensity_origin_id
            ],
            "process": "https://registry.core.trust.ib1.org/scheme/perseus/process/emissions-calculations/2024-12-05",
            "permissions": [cap_permission_id],
            "perseus:assurance": {
                "missingData": "https://registry.core.trust.ib1.org/scheme/perseus/assurance/missing-data/Substituted"
            }
        }
    )
    # - Add a transfer step to send it to the bank
    cap_record.add_step(
        {
            "type": "transfer",
            "scheme": "https://registry.core.trust.ib1.org/scheme/perseus",
            "of": cap_processing_id,
            "to": "https://directory.core.trust.ib1.org/member/71212388", # Bank
            "standard": "https://registry.core.trust.ib1.org/scheme/perseus/standard/emissions-report/2024-12-05",
            "licence": "https://registry.core.trust.ib1.org/scheme/perseus/licence/emissions-report/2024-12-05",
            "service": "https://api.emmissions4u.example.com/emission-report/23",
            "path": "/emissions",
            "parameters": {
                "from": "2023-09Z",
                "to": "2024-09Z"
            },
            "permissions": [cap_permission_id],
            "transaction": "C5813265-515B-48DC-925F-832FA418F7E2"
        }
    )

    # CAP signs the steps
    cap_record_signed = cap_record.sign(signer_cap)
    # Get encoded data for inclusion in data response
    cap_data_attachment = cap_record_signed.encoded()

    # -----------------------------------------------------------------------
    # ===== Bank retrieves the data from the CAP, who includes a provenance record in the response
    bank_record = Record(TRUST_FRAMEWORK_URL, cap_data_attachment)
    # - Verify the signatures on the record
    bank_record.verify(certificate_provider)
    # - Find the transfer step, passing in the expected values for the transfer step (exceptions if not found)
    transfer_from_cap_step = bank_record.find_step(
        {
            # Same values as the transfer step added by the CAP
            "type": "transfer",
            "scheme": "https://registry.core.trust.ib1.org/scheme/perseus",
            "to": "https://directory.core.trust.ib1.org/member/71212388", # Bank
            "standard": "https://registry.core.trust.ib1.org/scheme/perseus/standard/emissions-report/2024-12-05",
            "licence": "https://registry.core.trust.ib1.org/scheme/perseus/licence/emissions-report/2024-12-05",
            "service": "https://api.emmissions4u.example.com/emission-report/23",
            "path": "/emissions",
            "parameters": {
                "from": "2023-09Z",
                "to": "2024-09Z"
            }
        }
    )
    # - Add a receipt step
    bank_receipt_id = bank_record.add_step(
        {
            "type": "receipt",
            "transfer": transfer_from_cap_step["id"]
        }
    )

    # Bank signs the steps
    bank_record_signed = bank_record.sign(signer_bank)

    # ===== Final record after all the the steps have been added
    final_record = bank_record_signed

    # Print records
    print("----- Record (encoded for transfer) -----")
    print(json.dumps(final_record.encoded(), indent=2).encode("utf-8").decode("utf-8"))
    print("----- Decoded form of record including signature information -----")
    final_record.verify(certificate_provider)
    print(json.dumps(final_record.decoded(), indent=2).encode("utf-8").decode("utf-8"))
    print("----- Graphviz dot file -----")
    print(final_record.to_graphviz())

