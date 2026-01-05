# Frontend Integration Notes

This document provides critical information for frontend developers integrating with the RAGLOX API. It is based on the findings from the [Comprehensive Test Report](./COMPREHENSIVE_TEST_REPORT.md) and the [API Test Matrix](./API_TEST_MATRIX.md).

## Integration Guide

The RAGLOX API is a RESTful service. While it generally follows standard conventions, there are specific behaviors and deviations observed during testing that the frontend must account for to ensure a smooth user experience.

### Key Principles
1.  **Defensive Coding**: Do not assume the API will always return the "correct" HTTP status code as defined in the OpenAPI spec.
2.  **Client-Side Validation**: Validate inputs (especially UUIDs and limits) on the client side before sending requests to avoid ambiguous API errors.
3.  **Graceful Degradation**: When critical actions (like stopping a mission) fail with server errors, ensure the UI doesn't lock up.

## Gotchas & Workarounds

The following issues were identified during the comprehensive API testing. The frontend **must** implement these workarounds until the backend is patched.

### 1. Mission Stop Fails (Critical)
*   **Issue**: Calling `POST /api/v1/missions/{id}/stop` currently returns a **500 Internal Server Error**.
*   **Workaround**:
    *   **UI**: When the user clicks "Stop", show a loading state.
    *   **Logic**: If a 500 error is received, display a toast message: "Stop command sent, but server reported an internal error. Please refresh to check status."
    *   **State**: Do *not* optimistically update the UI to "Stopped" unless you confirm it via polling the mission status endpoint.

### 2. Approval & Mission Start "Not Found" Handling
*   **Issue**: Requests to non-existent missions for Approvals or Start actions return **400 Bad Request** instead of **404 Not Found**.
*   **Workaround**: Treat 400 errors on these endpoints as potential "Resource Not Found" scenarios if the request payload is known to be valid.

### 3. Invalid UUIDs
*   **Issue**: Sending an invalid UUID format (e.g., `invalid-id`) often returns **404 Not Found** instead of **422 Unprocessable Entity**.
*   **Workaround**: Strictly validate all UUIDs in the frontend using a library (e.g., `zod` or `uuid`) before making the request.

### 4. Chat History Limits
*   **Issue**: The backend does not validate the `limit` parameter for chat history.
*   **Workaround**: Enforce a reasonable limit (e.g., max 50 or 100) in the frontend UI/logic to prevent potential performance issues.

## Data Contracts & Observations

### Empty Lists vs. 404
*   **Observation**: For endpoints like `targets`, `vulnerabilities`, `credentials`, and `sessions`, requesting data for a **non-existent mission** often returns a **200 OK** with an empty list `[]` or empty object, rather than a **404 Not Found**.
*   **Implication**: If you receive an empty list, do not assume the mission exists. If context is required (e.g., you are on a Mission Details page), ensure you have successfully fetched the main Mission object (`GET /api/v1/missions/{id}`) first to confirm existence.

### Pagination
*   **Structure**: Endpoints supporting pagination (Knowledge Base, Nuclei) use `limit` and `offset`.
*   **Defaults**: Default limit is typically 50. Max limit is often 500.

## Error Handling Strategy

Recommended logic for your API client wrapper (e.g., Axios interceptors or fetch wrapper):

| HTTP Status | Observed Meaning | Recommended Frontend Action |
| :--- | :--- | :--- |
| **200 OK** | Success OR Non-existent resource (empty body) | Check body content. If empty when data expected, treat as "No Data" or verify parent resource. |
| **400 Bad Request** | Invalid Input OR Not Found (Approvals/Start) | Display error message. If action was "Start" or "Approve", consider refreshing the mission state. |
| **404 Not Found** | Resource Missing OR Invalid ID Format | Show "Not Found" page or toast. Ensure IDs are valid UUIDs. |
| **422 Unprocessable** | Validation Error | Show specific validation error from response details. |
| **500 Server Error** | Critical Failure (e.g., Stop Mission) | Show "System Error" toast. Log to monitoring. Allow user to retry non-destructive actions. |

## Reference Documents
*   [API Test Matrix](./API_TEST_MATRIX.md): Detailed list of all endpoints and expected behaviors.
*   [Comprehensive Test Report](./COMPREHENSIVE_TEST_REPORT.md): Full breakdown of pass/fail status and bugs.