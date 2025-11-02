# ClearlyDefined API Rate Limit Management

## Overview

The `ClearlyDefinedApi` class implements a rate-limit-aware request manager for the ClearlyDefined API. It addresses the issue of hitting rate limits by:

1. **Asynchronous Request Queue**: All requests are submitted to a queue and processed asynchronously
2. **Rate Limit Tracking**: Monitors `x-ratelimit-limit` and `x-ratelimit-remaining` response headers
3. **Automatic Retry**: Handles HTTP 429 (Too Many Requests) responses by re-queuing requests
4. **Fixed Thread Pool**: Uses 9 threads total (1 queue processor + 8 workers) for efficient processing
5. **Request Caching**: Caches successful responses to avoid duplicate requests

## Architecture

### Components

- **Request Queue**: A `BlockingQueue<ClearlyDefinedRequest>` that holds pending requests
- **Queue Processor Thread**: Single thread that monitors the queue and dispatches work
- **Worker Thread Pool**: 8 worker threads (`ExecutorService`) that process HTTP requests
- **Rate Limit State**: Atomic counters tracking remaining requests and reset time
- **Response Cache**: Concurrent map caching successful API responses

### Request Flow

```
Component → submitRequest() → Queue → Queue Processor → Worker Thread → HTTP Request
                                ↓                              ↓
                            Cache Hit?                    429 Response?
                                ↓                              ↓
                           Update Component              Re-queue Request
```

### Rate Limit Handling

The API tracks three key metrics from response headers:

1. **x-ratelimit-limit**: Total requests allowed in the current window
2. **x-ratelimit-remaining**: Requests remaining in the current window
3. **x-ratelimit-reset**: Timestamp when the rate limit resets (optional)

When `x-ratelimit-remaining` reaches 0:
- Queue processor pauses dispatching new requests
- If `x-ratelimit-reset` is available, waits until reset time
- Otherwise, implements exponential backoff

When a 429 response is received:
- Request is re-queued (up to MAX_RETRIES times)
- Rate limit counter is set to 0 to trigger waiting behavior
- Retry-After header is respected if present

## Usage

### In SBOMGenerator

```java
// Create API instance if ClearlyDefined fetching is enabled
clearlyDefinedApi = fetchClearlyDefined ? new ClearlyDefinedApi() : null;

// Submit async requests during component processing
clearlyDefinedApi.submitRequest(component, clearlyDefinedURI);

// Wait for all requests to complete at checkpoint
clearlyDefinedApi.waitForCompletion();

// Cleanup on shutdown
clearlyDefinedApi.shutdown();
```

### Response Headers Expected

The implementation expects ClearlyDefined API to return headers in the format:

```
x-ratelimit-limit: 100
x-ratelimit-remaining: 95
x-ratelimit-reset: 1234567890
```

Where:
- `x-ratelimit-limit`: Integer representing total requests allowed
- `x-ratelimit-remaining`: Integer representing remaining requests
- `x-ratelimit-reset`: Unix timestamp (seconds since epoch) for rate limit reset

## Configuration

Key constants in `ClearlyDefinedApi`:

```java
private static final int MAX_RETRIES = 3;        // Maximum retry attempts for failed requests
private static final int WORKER_THREADS = 8;      // Number of worker threads
private static final int TOTAL_THREADS = 9;       // Total threads (workers + queue processor)
```

## Error Handling

- **404 Responses**: Considered normal - component simply won't be enriched
- **429 Responses**: Automatic retry with rate limit respect
- **Other HTTP Errors**: Failed after MAX_RETRIES attempts
- **Network Errors**: Failed after MAX_RETRIES attempts
- **Bad JSON**: Logged but doesn't fail the request

## Testing

Tests verify:
- Basic lifecycle (creation, shutdown)
- Request submission returns CompletableFuture
- Wait for completion doesn't hang
- Cache works correctly for duplicate URIs
- Shutdown completes without errors

To test with actual ClearlyDefined API:
1. Enable `-clearly-defined` flag when running SBOM generator
2. Monitor console output for rate limit messages
3. Verify no HTTP 429 errors cascade to failures

## Performance Considerations

- **Parallelism**: Up to 8 concurrent HTTP requests
- **Queue Overhead**: Minimal - `LinkedBlockingQueue` is very efficient
- **Memory**: Caches all successful responses for session duration
- **Thread Safety**: All state is thread-safe using concurrent collections and atomics

## Future Enhancements

Potential improvements:
1. Make thread pool size configurable
2. Add metrics/logging for rate limit status
3. Implement persistent cache across sessions
4. Add configurable retry strategy
5. Support for multiple API endpoints with separate rate limits
