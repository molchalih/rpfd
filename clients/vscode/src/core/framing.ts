/**
 * The daemon's framing: one JSON object per line, on standard output.
 *
 * A line can be tens of megabytes, so chunks are held as they come and joined
 * once, when the newline that ends the line arrives.
 */

/** A stream of bytes cut into the lines the daemon writes. */
export class LineDecoder {
    private held: Buffer[] = [];
    private heldBytes = 0;

    /** Bytes of an unterminated line held so far. */
    get pending(): number {
        return this.heldBytes;
    }

    /**
     * Every complete line the chunk finished, without its newline. Empty lines
     * are dropped: the daemon never writes one.
     */
    push(chunk: Buffer): string[] {
        const lines: string[] = [];
        let from = 0;
        for (;;) {
            const end = chunk.indexOf(0x0a, from);
            if (end < 0) {
                break;
            }
            const piece = chunk.subarray(from, end);
            const line = this.heldBytes === 0 ? piece.toString('utf8') : this.take(piece);
            if (line.trim().length > 0) {
                lines.push(line);
            }
            from = end + 1;
        }
        if (from < chunk.length) {
            this.hold(chunk.subarray(from));
        }
        return lines;
    }

    private hold(piece: Buffer): void {
        this.held.push(piece);
        this.heldBytes += piece.length;
    }

    private take(last: Buffer): string {
        this.hold(last);
        const whole = Buffer.concat(this.held, this.heldBytes);
        this.held = [];
        this.heldBytes = 0;
        return whole.toString('utf8');
    }
}
