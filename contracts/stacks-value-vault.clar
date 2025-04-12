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
