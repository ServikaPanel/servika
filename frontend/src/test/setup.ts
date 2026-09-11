import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

// Testing Library unmounts after each test by itself only when the runner
// exposes `afterEach` as a global, and this configuration keeps globals off.
// Without this, every render stays mounted and the next test queries the
// previous one's screen as well.
afterEach(() => {
  cleanup()
})
