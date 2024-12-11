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
    # Certificate provider
    certificate_provider = CertificatesProviderSelfContainedRecord(
        "certs/4-signing-ca-cert.pem"
    )

    # Load signers
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

    # -----------------------------------------------------------------------
    # ===== Metering provider
    metering_record = Record(TRUST_FRAMEWORK_URL)
    # - Permission step to record consent by end user
    metering_permission_id = metering_record.add_step(
        {
            "type": "permission",
            "scheme": "https://registry.core.trust.ib1.org/scheme/supply",
            "timestamp": "2024-09-20T12:16:11Z",    # granted in past; must match audit trail
            "account": "/yl4Y/aV6b80fo5cnmuDDByfuEA=",
            "allows": {
                "licences": [
                    "https://registry.core.trust.ib1.org/scheme/supply/licence/metered-supply-data/2024-12-05"
                ]
            },
            "expires": "2025-09-20T12:16:11Z"       # 1 year
        }
    )
    # - Origin step for the smart meter data
    origin_id = metering_record.add_step(
        {
            "type": "origin",
            "scheme": "https://registry.core.trust.ib1.org/scheme/supply",
            "sourceType": "https://registry.core.trust.ib1.org/scheme/supply/source-type/Meter",
            "origin": "https://industrialmetering.example.com/",
            "external": False,
            "supply:scheme": {
                "meteringPeriod": {
                    "from": "2024-08-01Z",
                    "to": "2024-09-01Z"
                }
            },
            "supply:assurance": {
                "missingData": "https://registry.core.trust.ib1.org/scheme/supply/assurance/missing-data/Missing",
                "materialQuantity": "https://registry.core.trust.ib1.org/scheme/supply/assurance/material-quantity/Measured"
            }
        }
    )
    # - Transfer step to send it to the CAP
    metering_transfer_step_id = metering_record.add_step(
        {
            "type": "transfer",
            "scheme": "https://registry.core.trust.ib1.org/scheme/supply",
            "of": origin_id,
            "to": "https://directory.core.trust.ib1.org/member/293482",
            "standard": "https://registry.core.trust.ib1.org/scheme/supply/standard/metered-supply-data/2024-12-05",
            "licence": "https://registry.core.trust.ib1.org/scheme/supply/licence/metered-supply-data/2024-12-05",
            "service": "https://api.industrialmetering.example.com/meter-readings/0",
            "path": "/readings",
            "parameters": {
                "from": "2024-08-01Z",
                "to": "2024-09-01Z"
            },
            "permissions": [metering_permission_id],
            "transaction": "C25D0B85-B7C4-4543-B058-7DA57B8D9A24",
        }
    )
    # Metering provider signs the steps
    metering_record_signed = metering_record.sign(signers['6-industrial-metering-company'])
    # Get encoded data for inclusion in data response
    metering_data_attachment = metering_record_signed.encoded()

    # -----------------------------------------------------------------------
    # ===== CAP retrieves the data from the EDP, who includes a provenance record in the response
    manufacturer_record = Record(TRUST_FRAMEWORK_URL, metering_data_attachment)
    # - Verify the signatures on the record
    manufacturer_record.verify(certificate_provider)
    # - Add a receipt step
    manufacturer_receipt_id = manufacturer_record.add_step(
        {
            "type": "receipt",
            "transfer": metering_transfer_step_id
        }
    )
    # - Permission step to record consent to processing and future transfer
    manufacturer_permission_id = manufacturer_record.add_step(
        {
            "type": "permission",
            "scheme": "https://registry.core.trust.ib1.org/scheme/supply",
            "timestamp": "2024-10-21T09:09:10Z",
            "account": "dbd16978-a0a642d9aa2d95318b50e605",
            "allows": {
                "licences": [
                    "https://registry.core.trust.ib1.org/scheme/supply/licence/supply-data/2024-12-05"
                ],
                "processes": [
                    "https://registry.core.trust.ib1.org/scheme/supply/process/manufacture/2024-12-05"
                ]
            },
            "expires": "2025-10-21T09:09:10Z"       # 1 year
        }
    )
    # - Add an origin step for grid intensity data
    manufacturer_batch_origin_id = manufacturer_record.add_step(
        {
            "type": "origin",
            "scheme": "https://registry.core.trust.ib1.org/scheme/supply",
            "sourceType": "https://registry.core.trust.ib1.org/scheme/supply/source-type/GridCarbonIntensity",
            "origin": "https://api.carbonintensity.org.uk/",
            "originLicence": "https://creativecommons.org/licenses/by/4.0/",
            "external": True,
            "supply:scheme": {
                "meteringPeriod": {
                    "from": "2023-09-01Z",
                    "to": "2024-09-01Z"
                },
                "postcode": "CF99"
            },
            "supply:assurance": {
                "missingData": "https://registry.core.trust.ib1.org/scheme/supply/assurance/missing-data/Complete"
            }
        }
    )
    # - Add a process step to combine the data from the EDP and the grid intensity API into the report
    manufacturer_processing_id = manufacturer_record.add_step(
        {
            "type": "process",
            "scheme": "https://registry.core.trust.ib1.org/scheme/supply",
            "inputs": [
                manufacturer_receipt_id,
                manufacturer_batch_origin_id
            ],
            "process": "https://registry.core.trust.ib1.org/scheme/supply/process/manufacture/2024-12-05",
            "permissions": [manufacturer_permission_id],
            "supply:assurance": {
                "missingData": "https://registry.core.trust.ib1.org/scheme/supply/assurance/missing-data/Substituted",
                "audit": "https://registry.core.trust.ib1.org/scheme/supply/audit-standard/FS128983"
            }
        }
    )
    # - Add a transfer step to send it to the wholesaler
    manufacturer_transfer_step_id = manufacturer_record.add_step(
        {
            "type": "transfer",
            "scheme": "https://registry.core.trust.ib1.org/scheme/supply",
            "of": manufacturer_processing_id,
            "to": "https://directory.core.trust.ib1.org/member/927625",
            "standard": "https://registry.core.trust.ib1.org/scheme/supply/standard/supply-data/2024-12-05",
            "licence": "https://registry.core.trust.ib1.org/scheme/supply/licence/supply-data/2024-12-05",
            "service": "https://api.nitrofertiliser.example.com/supply",
            "path": "/supply",
            "parameters": {
                "invoiceNumber": "F2928-282847"
            },
            "permissions": [manufacturer_permission_id],
            "transaction": "C5813265-515B-48DC-925F-832FA418F7E2"
        }
    )

    manufacturer_record_signed = manufacturer_record.sign(signers['7-nitrogen-fertiliser-products'])
    # Get encoded data for inclusion in data response
    manufacturer_data_attachment = manufacturer_record_signed.encoded()

    # -----------------------------------------------------------------------
    # ===== Wholesaler
    wholesaler_record = Record(TRUST_FRAMEWORK_URL, manufacturer_data_attachment)
    # - Verify the signatures on the record
    wholesaler_record.verify(certificate_provider)
    # - Add a receipt step
    wholesaler_receipt_id = wholesaler_record.add_step(
        {
            "type": "receipt",
            "transfer": manufacturer_transfer_step_id
        }
    )
    wholesaler_permission_id = wholesaler_record.add_step(
        {
            "type": "permission",
            "scheme": "https://registry.core.trust.ib1.org/scheme/supply",
            "timestamp": "2024-10-21T09:09:10Z",
            "account": "hofgGwfwyZIhmM",
            "allows": {
                "licences": [
                    "https://registry.core.trust.ib1.org/scheme/supply/licence/supply-data/2024-12-05"
                ]
            },
            "expires": "2025-10-21T09:09:10Z"       # 1 year
        }
    )
    wholesaler_transfer_id = wholesaler_record.add_step(
        {
            "type": "transfer",
            "scheme": "https://registry.core.trust.ib1.org/scheme/supply",
            "of": wholesaler_receipt_id,
            "to": "https://directory.core.trust.ib1.org/member/143252",
            "standard": "https://registry.core.trust.ib1.org/scheme/supply/standard/supply-data/2024-12-05",
            "licence": "https://registry.core.trust.ib1.org/scheme/supply/licence/supply-data/2024-12-05",
            "service": "https://api.agwhole.example.com/supplies/v2",
            "path": "/supply",
            "parameters": {
                "invoiceNumber": "876256237"
            },
            "permissions": [wholesaler_permission_id],
            "transaction": "00FA5C42-DDBB-444C-B1CE-7B45C0DA642F"
        }
    )

    wholesaler_record_signed = wholesaler_record.sign(signers["8-agricultural-wholesale-supplies"])
    wholesaler_data_attachment = wholesaler_record_signed.encoded()

    # -----------------------------------------------------------------------
    # ===== Farm management system
    farm_management_system_record = Record(TRUST_FRAMEWORK_URL, wholesaler_data_attachment)


    farm_management_system_receipt_id = farm_management_system_record.add_step(
        {
            "type": "receipt",
            "transfer": wholesaler_transfer_id
        }
    )

    farm_management_system_record_signed = farm_management_system_record.sign(signers["9-precise-farm-automation-co"])


    # ===== Final record after all the the steps have been added
    final_record = farm_management_system_record_signed

    # Print records
    print("----- Record (encoded for transfer) -----")
    print(json.dumps(final_record.encoded(), indent=2).encode("utf-8").decode("utf-8"))
    print("----- Decoded form of record including signature information -----")
    final_record.verify(certificate_provider)
    print(json.dumps(final_record.decoded(), indent=2).encode("utf-8").decode("utf-8"))
    print("----- Graphviz dot file -----")
    print(final_record.to_graphviz())

