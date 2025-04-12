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
