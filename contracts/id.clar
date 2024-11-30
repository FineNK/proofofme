;; ProofOfMe - Decentralized Identity Management Contract
;; A self-sovereign identity system with privacy-preserving verification

(define-data-var admin principal tx-sender)

;; Data structures for identity records
(define-map identities
    principal
    {
        did: (string-utf8 50),              ;; Decentralized identifier
        metadata-hash: (buff 32),           ;; IPFS hash of encrypted metadata
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

;; Constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-REGISTERED (err u101))
(define-constant ERR-NOT-REGISTERED (err u102))
(define-constant ERR-INVALID-VERIFIER (err u103))

;; Initialize contract
(define-public (initialize-contract)
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
        (ok true)))

;; Register new identity
(define-public (register-identity (did (string-utf8 50)) (metadata-hash (buff 32)))
    (let ((existing-identity (map-get? identities tx-sender)))
        (asserts! (is-none existing-identity) ERR-ALREADY-REGISTERED)
        (ok (map-set identities tx-sender
            {
                did: did,
                metadata-hash: metadata-hash,
                verification-status: false,
                created-at: block-height,
                last-updated: block-height
            }))))

;; Update identity metadata
(define-public (update-metadata (new-metadata-hash (buff 32)))
    (let ((identity (unwrap! (map-get? identities tx-sender) ERR-NOT-REGISTERED)))
        (ok (map-set identities tx-sender
            (merge identity
                {
                    metadata-hash: new-metadata-hash,
                    last-updated: block-height
                })))))

;; Add verifier
(define-public (add-verifier (verifier-principal principal) (verifier-name (string-utf8 50)))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) ERR-NOT-AUTHORIZED)
        (ok (map-set verifiers verifier-principal
            {
                name: verifier-name,
                status: true,
                verification-count: u0
            }))))

;; Verify identity
(define-public (verify-identity (identity-owner principal))
    (let (
        (verifier (unwrap! (map-get? verifiers tx-sender) ERR-INVALID-VERIFIER))
        (identity (unwrap! (map-get? identities identity-owner) ERR-NOT-REGISTERED))
    )
    (ok (map-set identities identity-owner
        (merge identity
            {
                verification-status: true,
                last-updated: block-height
            })))))

;; Read-only functions
(define-read-only (get-identity (identity-owner principal))
    (map-get? identities identity-owner))

(define-read-only (is-verified (identity-owner principal))
    (match (map-get? identities identity-owner)
        identity (ok (get verification-status identity))
        ERR-NOT-REGISTERED))

(define-read-only (get-verifier-info (verifier-principal principal))
    (map-get? verifiers verifier-principal))