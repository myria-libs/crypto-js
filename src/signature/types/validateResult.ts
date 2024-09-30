export enum ValidationResult {
    // The validation is success
    VALID = "VALID",
    // The validation is failed
    INVALID = "INVALID",
    // The validation is success but already expired. We can consider as INVALID but to let it more declarative
    EXPIRED = "EXPIRED",
}
