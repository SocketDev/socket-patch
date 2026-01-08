/**
 * Lightweight terminal spinner for CLI progress indication.
 * Compatible with socket-cli's spinner patterns but standalone.
 */

// Spinner frames - matches the 'dots' style from socket-cli
const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
const SPINNER_INTERVAL = 80 // ms

// CI-friendly spinner (no animation)
const CI_FRAMES = ['-']
const CI_INTERVAL = 1000

export interface SpinnerOptions {
  /** Stream to write to (default: process.stderr) */
  stream?: NodeJS.WriteStream
  /** Use CI mode (no animation) */
  ci?: boolean
  /** Disable spinner entirely (for JSON output) */
  disabled?: boolean
}

export class Spinner {
  private stream: NodeJS.WriteStream
  private frames: string[]
  private interval: number
  private frameIndex = 0
  private text = ''
  private timer: ReturnType<typeof setInterval> | null = null
  private disabled: boolean

  constructor(options: SpinnerOptions = {}) {
    this.stream = options.stream ?? process.stderr
    this.disabled = options.disabled ?? false

    // Use CI mode if explicitly requested or if not a TTY
    const useCi = options.ci ?? !this.stream.isTTY
    this.frames = useCi ? CI_FRAMES : SPINNER_FRAMES
    this.interval = useCi ? CI_INTERVAL : SPINNER_INTERVAL
  }

  /**
   * Check if spinner is currently active
   */
  get isSpinning(): boolean {
    return this.timer !== null
  }

  /**
   * Start the spinner with optional text
   */
  start(text?: string): this {
    if (this.disabled) return this

    // Stop any existing spinner
    if (this.timer) {
      this.stop()
    }

    this.text = text ?? ''
    this.frameIndex = 0

    // Render immediately
    this.render()

    // Start animation
    this.timer = setInterval(() => {
      this.frameIndex = (this.frameIndex + 1) % this.frames.length
      this.render()
    }, this.interval)

    return this
  }

  /**
   * Update the spinner text without stopping
   */
  update(text: string): this {
    if (this.disabled) return this
    this.text = text
    if (this.isSpinning) {
      this.render()
    }
    return this
  }

  /**
   * Stop the spinner and clear the line
   */
  stop(): this {
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = null
    }
    this.clear()
    return this
  }

  /**
   * Stop the spinner with a success message
   */
  succeed(text?: string): this {
    this.stopWithSymbol('✓', text)
    return this
  }

  /**
   * Stop the spinner with a failure message
   */
  fail(text?: string): this {
    this.stopWithSymbol('✗', text)
    return this
  }

  /**
   * Stop the spinner with an info message
   */
  info(text?: string): this {
    this.stopWithSymbol('ℹ', text)
    return this
  }

  /**
   * Clear the current line
   */
  private clear(): void {
    if (!this.stream.isTTY) return
    // Move cursor to beginning and clear the line
    this.stream.write('\r\x1b[K')
  }

  /**
   * Render the current spinner frame with text
   */
  private render(): void {
    if (!this.stream.isTTY) {
      // In non-TTY mode, just write text on new lines occasionally
      return
    }

    const frame = this.frames[this.frameIndex]
    const line = this.text ? `${frame} ${this.text}` : frame

    // Clear line and write new content
    this.stream.write(`\r\x1b[K${line}`)
  }

  /**
   * Stop spinner with a symbol and optional final text
   */
  private stopWithSymbol(symbol: string, text?: string): void {
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = null
    }

    if (this.disabled) return

    const finalText = text ?? this.text
    if (finalText && this.stream.isTTY) {
      this.stream.write(`\r\x1b[K${symbol} ${finalText}\n`)
    } else if (finalText) {
      this.stream.write(`${symbol} ${finalText}\n`)
    } else {
      this.clear()
    }
  }
}

/**
 * Create a new spinner instance
 */
export function createSpinner(options?: SpinnerOptions): Spinner {
  return new Spinner(options)
}
