;; SecureDigital Asset Exchange Protocol
;; A blockchain-based escrow system for secure digital asset transactions

;; Global configuration and error management
(define-constant CONTRACT_ADMIN tx-sender)
(define-constant ERROR_NOT_PERMITTED (err u1000))
(define-constant ERROR_ESCROW_NOT_FOUND (err u1001))
(define-constant ERROR_STATE_INVALID (err u1002))
(define-constant ERROR_TRANSACTION_FAILED (err u1003))
(define-constant ERROR_BAD_ID (err u1004))
(define-constant ERROR_BAD_PARAMETER (err u1005))
(define-constant ERROR_INVALID_COUNTERPARTY (err u1006))
(define-constant ERROR_TIME_EXPIRED (err u1007))
(define-constant DEFAULT_DURATION_BLOCKS u1008) 

;; Transaction data storage
(define-map TransactionRegistry
  { tx-id: uint }
  {
    purchasing-party: principal,
    selling-party: principal,
    digital-item-id: uint,
    payment-amount: uint,
    tx-phase: (string-ascii 10),
    initiation-height: uint,
    termination-height: uint
  }
)

;; Transaction counter for unique identifier assignment
(define-data-var transaction-counter uint u0)

;; -------------------------------------------------------------
;; Internal Validation Functions
;; -------------------------------------------------------------

;; Ensure counterparty is not the same as transaction initiator
(define-private (validate-counterparty (counterparty principal))
  (and 
    (not (is-eq counterparty tx-sender))
    (not (is-eq counterparty (as-contract tx-sender)))
  )
)

;; Check if transaction ID exists in registry
(define-private (validate-transaction-exists (tx-id uint))
  (<= tx-id (var-get transaction-counter))
)

;; -------------------------------------------------------------
;; Core Transaction Functions
;; -------------------------------------------------------------

;; Complete transaction and release funds to selling party
(define-public (complete-transaction (tx-id uint))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (selling-party (get selling-party tx-details))
        (payment-amount (get payment-amount tx-details))
        (digital-item-id (get digital-item-id tx-details))
      )
      (asserts! (or (is-eq tx-sender CONTRACT_ADMIN) (is-eq tx-sender (get purchasing-party tx-details))) ERROR_NOT_PERMITTED)
      (asserts! (is-eq (get tx-phase tx-details) "pending") ERROR_STATE_INVALID)
      (asserts! (<= block-height (get termination-height tx-details)) ERROR_TIME_EXPIRED)
      (match (as-contract (stx-transfer? payment-amount tx-sender selling-party))
        success-result
          (begin
            (map-set TransactionRegistry
              { tx-id: tx-id }
              (merge tx-details { tx-phase: "fulfilled" })
            )
            (print {event: "transaction_completed", tx-id: tx-id, seller: selling-party, digital-item-id: digital-item-id, payment-amount: payment-amount})
            (ok true)
          )
        failure-result ERROR_TRANSACTION_FAILED
      )
    )
  )
)

;; Return funds to purchaser in case of transaction cancellation
(define-public (return-funds (tx-id uint))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (purchasing-party (get purchasing-party tx-details))
        (payment-amount (get payment-amount tx-details))
      )
      (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERROR_NOT_PERMITTED)
      (asserts! (is-eq (get tx-phase tx-details) "pending") ERROR_STATE_INVALID)
      (match (as-contract (stx-transfer? payment-amount tx-sender purchasing-party))
        success-result
          (begin
            (map-set TransactionRegistry
              { tx-id: tx-id }
              (merge tx-details { tx-phase: "returned" })
            )
            (print {event: "funds_returned", tx-id: tx-id, purchaser: purchasing-party, payment-amount: payment-amount})
            (ok true)
          )
        failure-result ERROR_TRANSACTION_FAILED
      )
    )
  )
)

;; Create cryptographic verification challenge-response system
(define-public (initiate-verification-challenge (tx-id uint) (challenge-nonce (buff 32)) 
                                              (response-timeout uint) (challenge-target principal))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (purchasing-party (get purchasing-party tx-details))
        (selling-party (get selling-party tx-details))
      )
      ;; Authorization check
      (asserts! (or (is-eq tx-sender purchasing-party) 
                   (is-eq tx-sender selling-party)
                   (is-eq tx-sender CONTRACT_ADMIN)) 
                ERROR_NOT_PERMITTED)

      ;; Validate transaction is in appropriate state
      (asserts! (or (is-eq (get tx-phase tx-details) "pending")
                   (is-eq (get tx-phase tx-details) "disputed"))
                ERROR_STATE_INVALID)

      ;; Validate challenge target is transaction participant
      (asserts! (or (is-eq challenge-target purchasing-party) 
                   (is-eq challenge-target selling-party))
                (err u1380))

      ;; Ensure challenger isn't challenging themselves
      (asserts! (not (is-eq challenge-target tx-sender)) (err u1381))

      ;; Validate timeout
      (asserts! (>= response-timeout u12) ERROR_BAD_PARAMETER) ;; Minimum 2 hours (12 blocks)
      (asserts! (<= response-timeout u144) (err u1382)) ;; Maximum 24 hours (144 blocks)

      ;; Calculate challenge expiration
      (let
        (
          (challenge-expiry (+ block-height response-timeout))
        )
          (print {event: "verification_challenge_initiated", tx-id: tx-id, 
                  challenger: tx-sender, challenged: challenge-target,
                  nonce: challenge-nonce, expires-at: challenge-expiry})
          (ok challenge-expiry)
      )
    )
  )
)

;; Sets up a multi-signature approval requirement for high-value transactions
(define-public (setup-multi-signature-requirement (tx-id uint) (required-approvers (list 5 principal)) (approval-threshold uint))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (payment-amount (get payment-amount tx-details))
        (purchasing-party (get purchasing-party tx-details))
      )
      ;; Only purchaser can setup multi-signature requirements
      (asserts! (is-eq tx-sender purchasing-party) ERROR_NOT_PERMITTED)
      ;; Only for transactions in pending phase
      (asserts! (is-eq (get tx-phase tx-details) "pending") ERROR_STATE_INVALID)
      ;; Only for high-value transactions (> 2000 STX)
      (asserts! (> payment-amount u2000) (err u1230))
      ;; Check valid approver count (2-5 approvers allowed)
      (asserts! (> (len required-approvers) u1) ERROR_BAD_PARAMETER)
      ;; Ensure threshold is valid (must be at least 2 and not more than the number of approvers)
      (asserts! (>= approval-threshold u2) ERROR_BAD_PARAMETER)
      (asserts! (<= approval-threshold (len required-approvers)) ERROR_BAD_PARAMETER)

      (print {event: "multi_signature_setup", tx-id: tx-id, purchaser: purchasing-party, 
              approvers: required-approvers, threshold: approval-threshold})
      (ok true)
    )
  )
)

;; Abort transaction by purchasing party
(define-public (abort-transaction (tx-id uint))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (purchasing-party (get purchasing-party tx-details))
        (payment-amount (get payment-amount tx-details))
      )
      (asserts! (is-eq tx-sender purchasing-party) ERROR_NOT_PERMITTED)
      (asserts! (is-eq (get tx-phase tx-details) "pending") ERROR_STATE_INVALID)
      (asserts! (<= block-height (get termination-height tx-details)) ERROR_TIME_EXPIRED)
      (match (as-contract (stx-transfer? payment-amount tx-sender purchasing-party))
        success-result
          (begin
            (map-set TransactionRegistry
              { tx-id: tx-id }
              (merge tx-details { tx-phase: "aborted" })
            )
            (print {event: "transaction_aborted", tx-id: tx-id, purchaser: purchasing-party, payment-amount: payment-amount})
            (ok true)
          )
        failure-result ERROR_TRANSACTION_FAILED
      )
    )
  )
)

;; Implement transaction rate limiting for an address to prevent spam attacks
(define-public (enforce-rate-limiting (address principal) (max-daily-transactions uint) (cooldown-period uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERROR_NOT_PERMITTED)
    (asserts! (> max-daily-transactions u0) ERROR_BAD_PARAMETER)
    (asserts! (<= max-daily-transactions u100) ERROR_BAD_PARAMETER) ;; Maximum 100 transactions per day
    (asserts! (>= cooldown-period u6) ERROR_BAD_PARAMETER) ;; Minimum 6 blocks (~1 hour)
    (asserts! (<= cooldown-period u144) ERROR_BAD_PARAMETER) ;; Maximum 24 hours (144 blocks)

    ;; If implementing a full solution, would use maps to track transaction counts
    ;; and timestamps for each address

    ;; For high-risk addresses, can apply stricter limitations
    (let
      (
        (effective-period (if (> max-daily-transactions u50) 
                             cooldown-period 
                             (+ cooldown-period u6))) ;; Add extra cooldown for higher limits
      )
      (print {event: "rate_limiting_enforced", address: address, max-daily-tx: max-daily-transactions, 
              cooldown: effective-period, enforcer: tx-sender})
      (ok effective-period)
    )
  )
)

;; Modify transaction time window
(define-public (modify-timeframe (tx-id uint) (additional-blocks uint))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (asserts! (> additional-blocks u0) ERROR_BAD_PARAMETER)
    (asserts! (<= additional-blocks u1440) ERROR_BAD_PARAMETER) ;; Maximum 10 days extension
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (purchasing-party (get purchasing-party tx-details)) 
        (selling-party (get selling-party tx-details))
        (current-termination (get termination-height tx-details))
        (updated-termination (+ current-termination additional-blocks))
      )
      (asserts! (or (is-eq tx-sender purchasing-party) (is-eq tx-sender selling-party) (is-eq tx-sender CONTRACT_ADMIN)) ERROR_NOT_PERMITTED)
      (asserts! (or (is-eq (get tx-phase tx-details) "pending") (is-eq (get tx-phase tx-details) "accepted")) ERROR_STATE_INVALID)
      (map-set TransactionRegistry
        { tx-id: tx-id }
        (merge tx-details { termination-height: updated-termination })
      )
      (print {event: "timeframe_modified", tx-id: tx-id, requestor: tx-sender, new-termination: updated-termination})
      (ok true)
    )
  )
)

;; Process expired transaction - returns funds to purchaser
(define-public (process-expired-transaction (tx-id uint))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (purchasing-party (get purchasing-party tx-details))
        (payment-amount (get payment-amount tx-details))
        (expiration (get termination-height tx-details))
      )
      (asserts! (or (is-eq tx-sender purchasing-party) (is-eq tx-sender CONTRACT_ADMIN)) ERROR_NOT_PERMITTED)
      (asserts! (or (is-eq (get tx-phase tx-details) "pending") (is-eq (get tx-phase tx-details) "accepted")) ERROR_STATE_INVALID)
      (asserts! (> block-height expiration) (err u1008)) ;; Must be expired
      (match (as-contract (stx-transfer? payment-amount tx-sender purchasing-party))
        success-result
          (begin
            (map-set TransactionRegistry
              { tx-id: tx-id }
              (merge tx-details { tx-phase: "expired" })
            )
            (print {event: "expired_transaction_processed", tx-id: tx-id, purchaser: purchasing-party, payment-amount: payment-amount})
            (ok true)
          )
        failure-result ERROR_TRANSACTION_FAILED
      )
    )
  )
)

;; Implement emergency transaction freeze with timelock for critical security incidents
(define-public (emergency-transaction-freeze (tx-id uint) (freeze-reason (string-ascii 100)) (freeze-duration uint))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (asserts! (> freeze-duration u6) ERROR_BAD_PARAMETER) ;; Minimum 1 hour freeze (6 blocks)
    (asserts! (<= freeze-duration u720) ERROR_BAD_PARAMETER) ;; Maximum 5 days freeze (720 blocks)

    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (current-phase (get tx-phase tx-details))
        (unfreeze-height (+ block-height freeze-duration))
      )
      ;; Can only freeze active transactions
      (asserts! (or (is-eq current-phase "pending") 
                   (is-eq current-phase "accepted")) 
                ERROR_STATE_INVALID)

      ;; Update transaction state to frozen
      (map-set TransactionRegistry
        { tx-id: tx-id }
        (merge tx-details { 
          tx-phase: "frozen",
          termination-height: (+ (get termination-height tx-details) freeze-duration) ;; Extend deadline
        })
      )

      (print {event: "emergency_freeze", tx-id: tx-id, reason: freeze-reason, 
              initiated-by: tx-sender, duration: freeze-duration, unfreeze-at: unfreeze-height})
      (ok unfreeze-height)
    )
  )
)

;; Initiate dispute resolution process
(define-public (initiate-dispute (tx-id uint) (dispute-details (string-ascii 50)))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (purchasing-party (get purchasing-party tx-details))
        (selling-party (get selling-party tx-details))
      )
      (asserts! (or (is-eq tx-sender purchasing-party) (is-eq tx-sender selling-party)) ERROR_NOT_PERMITTED)
      (asserts! (or (is-eq (get tx-phase tx-details) "pending") (is-eq (get tx-phase tx-details) "accepted")) ERROR_STATE_INVALID)
      (asserts! (<= block-height (get termination-height tx-details)) ERROR_TIME_EXPIRED)
      (map-set TransactionRegistry
        { tx-id: tx-id }
        (merge tx-details { tx-phase: "disputed" })
      )
      (print {event: "dispute_initiated", tx-id: tx-id, initiator: tx-sender, details: dispute-details})
      (ok true)
    )
  )
)

;; Submit cryptographic verification for transaction
(define-public (submit-verification (tx-id uint) (cryptographic-proof (buff 65)))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (purchasing-party (get purchasing-party tx-details))
        (selling-party (get selling-party tx-details))
      )
      (asserts! (or (is-eq tx-sender purchasing-party) (is-eq tx-sender selling-party)) ERROR_NOT_PERMITTED)
      (asserts! (or (is-eq (get tx-phase tx-details) "pending") (is-eq (get tx-phase tx-details) "accepted")) ERROR_STATE_INVALID)
      (print {event: "verification_submitted", tx-id: tx-id, submitter: tx-sender, proof: cryptographic-proof})
      (ok true)
    )
  )
)

;; Implement tiered verification requirements based on transaction value
(define-public (set-verification-tier (tx-id uint) (tier-level uint))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERROR_NOT_PERMITTED)
    (asserts! (>= tier-level u1) ERROR_BAD_PARAMETER)
    (asserts! (<= tier-level u3) ERROR_BAD_PARAMETER) ;; Three tiers available: 1=basic, 2=enhanced, 3=maximum

    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (payment-amount (get payment-amount tx-details))
        (purchasing-party (get purchasing-party tx-details))
        (selling-party (get selling-party tx-details))
      )
      ;; Ensure transaction is in an appropriate phase
      (asserts! (is-eq (get tx-phase tx-details) "pending") ERROR_STATE_INVALID)

      ;; Verify tier level is appropriate for transaction value
      (asserts! (or 
                 (and (is-eq tier-level u1) (< payment-amount u1000))
                 (and (is-eq tier-level u2) (and (>= payment-amount u1000) (< payment-amount u10000)))
                 (and (is-eq tier-level u3) (>= payment-amount u10000))
                ) 
                (err u1240))

      ;; In a complete implementation, this would set specific verification requirements
      ;; based on the tier level in a separate map

      (print {event: "verification_tier_set", tx-id: tx-id, tier: tier-level, 
              purchaser: purchasing-party, seller: selling-party, amount: payment-amount})
      (ok tier-level)
    )
  )
)

;; Register backup recovery address
(define-public (register-recovery-address (tx-id uint) (recovery-address principal))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (purchasing-party (get purchasing-party tx-details))
      )
      (asserts! (is-eq tx-sender purchasing-party) ERROR_NOT_PERMITTED)
      (asserts! (not (is-eq recovery-address tx-sender)) (err u1111)) ;; Recovery address must be different
      (asserts! (is-eq (get tx-phase tx-details) "pending") ERROR_STATE_INVALID)
      (print {event: "recovery_address_registered", tx-id: tx-id, purchaser: purchasing-party, recovery: recovery-address})
      (ok true)
    )
  )
)

;; Resolve dispute with proportional fund allocation
(define-public (resolve-dispute (tx-id uint) (purchaser-percentage uint))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (asserts! (is-eq tx-sender CONTRACT_ADMIN) ERROR_NOT_PERMITTED)
    (asserts! (<= purchaser-percentage u100) ERROR_BAD_PARAMETER) ;; Percentage must be 0-100
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (purchasing-party (get purchasing-party tx-details))
        (selling-party (get selling-party tx-details))
        (payment-amount (get payment-amount tx-details))
        (purchaser-allocation (/ (* payment-amount purchaser-percentage) u100))
        (seller-allocation (- payment-amount purchaser-allocation))
      )
      (asserts! (is-eq (get tx-phase tx-details) "disputed") (err u1112)) ;; Must be disputed
      (asserts! (<= block-height (get termination-height tx-details)) ERROR_TIME_EXPIRED)

      ;; Transfer purchaser's share
      (unwrap! (as-contract (stx-transfer? purchaser-allocation tx-sender purchasing-party)) ERROR_TRANSACTION_FAILED)

      ;; Transfer seller's share
      (unwrap! (as-contract (stx-transfer? seller-allocation tx-sender selling-party)) ERROR_TRANSACTION_FAILED)

      (map-set TransactionRegistry
        { tx-id: tx-id }
        (merge tx-details { tx-phase: "resolved" })
      )
      (print {event: "dispute_resolved", tx-id: tx-id, purchaser: purchasing-party, seller: selling-party, 
              purchaser-amount: purchaser-allocation, seller-amount: seller-allocation, purchaser-percentage: purchaser-percentage})
      (ok true)
    )
  )
)

;; Add secondary verification for high-value transactions
(define-public (add-secondary-validation (tx-id uint) (validator principal))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (purchasing-party (get purchasing-party tx-details))
        (payment-amount (get payment-amount tx-details))
      )
      ;; Only apply to transactions above threshold
      (asserts! (> payment-amount u1000) (err u1120))
      (asserts! (or (is-eq tx-sender purchasing-party) (is-eq tx-sender CONTRACT_ADMIN)) ERROR_NOT_PERMITTED)
      (asserts! (is-eq (get tx-phase tx-details) "pending") ERROR_STATE_INVALID)
      (print {event: "secondary_validation_added", tx-id: tx-id, validator: validator, requestor: tx-sender})
      (ok true)
    )
  )
)

;; Add trusted external oracle verification for high-value transactions
(define-public (register-oracle-verification (tx-id uint) (oracle-principal principal) (verification-type (string-ascii 20)))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (payment-amount (get payment-amount tx-details))
        (purchasing-party (get purchasing-party tx-details))
        (selling-party (get selling-party tx-details))
      )
      ;; Verify authorization
      (asserts! (or (is-eq tx-sender purchasing-party) 
                   (is-eq tx-sender selling-party)
                   (is-eq tx-sender CONTRACT_ADMIN)) 
                ERROR_NOT_PERMITTED)

      ;; Verify transaction is in appropriate state
      (asserts! (is-eq (get tx-phase tx-details) "pending") ERROR_STATE_INVALID)

      ;; Validate oracle is not a party to the transaction
      (asserts! (not (is-eq oracle-principal purchasing-party)) (err u1250))
      (asserts! (not (is-eq oracle-principal selling-party)) (err u1251))

      ;; Validate verification type is supported
      (asserts! (or (is-eq verification-type "identity-check")
                   (is-eq verification-type "asset-validation")
                   (is-eq verification-type "risk-assessment")
                   (is-eq verification-type "regulatory-compliance"))
                (err u1252))

      ;; For high-value transactions only
      (asserts! (> payment-amount u5000) (err u1253))

      (print {event: "oracle_verification_registered", tx-id: tx-id, 
              oracle: oracle-principal, type: verification-type, 
              requester: tx-sender, amount: payment-amount})
      (ok true)
    )
  )
)

;; Security lockdown for suspicious activity
(define-public (security-lockdown (tx-id uint) (security-notes (string-ascii 100)))
  (begin
    (asserts! (validate-transaction-exists tx-id) ERROR_BAD_ID)
    (let
      (
        (tx-details (unwrap! (map-get? TransactionRegistry { tx-id: tx-id }) ERROR_ESCROW_NOT_FOUND))
        (purchasing-party (get purchasing-party tx-details))
        (selling-party (get selling-party tx-details))
      )
      (asserts! (or (is-eq tx-sender CONTRACT_ADMIN) (is-eq tx-sender purchasing-party) (is-eq tx-sender selling-party)) ERROR_NOT_PERMITTED)
      (asserts! (or (is-eq (get tx-phase tx-details) "pending") 
                   (is-eq (get tx-phase tx-details) "accepted")) 
                ERROR_STATE_INVALID)
      (map-set TransactionRegistry
        { tx-id: tx-id }
        (merge tx-details { tx-phase: "locked" })
      )
      (print {event: "security_lockdown", tx-id: tx-id, initiator: tx-sender, reason: security-notes})
      (ok true)
    )
  )
)
