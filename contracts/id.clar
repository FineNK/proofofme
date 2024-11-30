;; ProofOfMe - Decentralized Identity Management Contract
;; A self-sovereign identity system with privacy-preserving verification

(define-data-var admin principal tx-sender)

;; Constants for validation
(define-constant MIN-DID-LENGTH u10)
(define-constant METADATA-HASH-LENGTH u32)
(define-constant MIN-NAME-LENGTH u3)
(define-constant MAX-NAME-LENGTH u50)
(define-constant DID-PREFIX "did:")

;; Error constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-REGISTERED (err u101))
(define-constant ERR-NOT-REGISTERED (err u102))
(define-constant ERR-INVALID-VERIFIER (err u103))
(define-constant ERR-INVALID-DID (err u104))
(define-constant ERR-INVALID-METADATA (err u105))
(define-constant ERR-INVALID-NAME (err u106))
(define-constant ERR-SELF-VERIFICATION (err u107))

;; Data structures for identity records
(define-map identities
    principal
    {
        did: (string-utf8 50),
        metadata-hash: (buff 32),
        verification-status: bool,
        created-at: uint,
        last-updated: uint
    }
)

;; Map to store verification authorities
(define-map verifiers
    principal
    {
        name: (string-utf8 50),
        status: bool,
        verification-count: uint
    }
)

;; Validation functions
(define-private (is-valid-did (did (string-utf8 50)))
    (let ((length (len did)))
        (and 
            (>= length MIN-DID-LENGTH)
            (<= length MAX-NAME-LENGTH)
            (is-eq (get-substring? did u0 u4) (some DID-PREFIX))
        )
    )
)

(define-private (is-valid-metadata-hash (hash (buff 32)))
    (is-eq (len hash) METADATA-HASH-LENGTH)
)

(define-private (is-valid-name (name (string-utf8 50)))
    (let ((length (len name)))
        (and 
            (>= length MIN-NAME-LENGTH)
            (<= length MAX-NAME-LENGTH)
        )
    )
)

;; Initialize contract
(define-public (initialize-contract)
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
        (ok true)))

;; Register new identity with validation
(define-public (register-identity (did (string-utf8 50)) (metadata-hash (buff 32)))
    (begin
        (asserts! (is-valid-did did) ERR-INVALID-DID)
        (asserts! (is-valid-metadata-hash metadata-hash) ERR-INVALID-METADATA)
        (asserts! (is-none (map-get? identities tx-sender)) ERR-ALREADY-REGISTERED)
        (ok (map-set identities tx-sender
            {
                did: did,
                metadata-hash: metadata-hash,
                verification-status: false,
                created-at: block-height,
                last-updated: block-height
            }))))

;; Update identity metadata with validation
(define-public (update-metadata (new-metadata-hash (buff 32)))
    (begin
        (asserts! (is-valid-metadata-hash new-metadata-hash) ERR-INVALID-METADATA)
        (match (map-get? identities tx-sender)
            identity (ok (map-set identities tx-sender
                (merge identity
                    {
                        metadata-hash: new-metadata-hash,
                        last-updated: block-height
                    })))
            ERR-NOT-REGISTERED)))

;; Add verifier with validation
(define-public (add-verifier (verifier-principal principal) (verifier-name (string-utf8 50)))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
        (asserts! (is-valid-name verifier-name) ERR-INVALID-NAME)
        (asserts! (not (is-eq verifier-principal tx-sender)) ERR-SELF-VERIFICATION)
        (ok (map-set verifiers verifier-principal
            {
                name: verifier-name,
                status: true,
                verification-count: u0
            }))))

;; Verify identity with safety checks
(define-public (verify-identity (identity-owner principal))
    (begin
        (asserts! (not (is-eq identity-owner tx-sender)) ERR-SELF-VERIFICATION)
        (match (map-get? verifiers tx-sender)
            verifier (match (map-get? identities identity-owner)
                identity (ok (map-set identities identity-owner
                    (merge identity
                        {
                            verification-status: true,
                            last-updated: block-height
                        })))
                ERR-NOT-REGISTERED)
            ERR-INVALID-VERIFIER)))

;; Read-only functions
(define-read-only (get-identity (identity-owner principal))
    (map-get? identities identity-owner))

(define-read-only (is-verified (identity-owner principal))
    (match (map-get? identities identity-owner)
        identity (ok (get verification-status identity))
        ERR-NOT-REGISTERED))

(define-read-only (get-verifier-info (verifier-principal principal))
    (map-get? verifiers verifier-principal))