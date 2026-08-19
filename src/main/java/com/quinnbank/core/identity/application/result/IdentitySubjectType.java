package com.quinnbank.core.identity.application.result;

/**
 * Stable application-contract classification for the business subject represented by an identity.
 */
public enum IdentitySubjectType {
    RETAIL_CUSTOMER,
    BUSINESS_CUSTOMER,
    BANK_EMPLOYEE,
    BACK_OFFICE_OPERATOR,
    SERVICE_ACCOUNT,
    THIRD_PARTY_PARTNER,
    BATCH_JOB
}
