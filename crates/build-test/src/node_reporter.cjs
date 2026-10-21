// Stream actual node:test events, including runtime discovery and console data.
// File-load wrappers are classified by the Rust/Python adapter, not counted as
// successful behavioral tests merely because Node loaded a file.
module.exports = async function* reporter(events) {
  for await (const event of events) {
    yield JSON.stringify(event, (_key, value) => {
      if (value instanceof Error) {
        return {message: value.message, code: value.code,
          failureType: value.failureType, stack: value.stack};
      }
      return typeof value === 'bigint' ? value.toString() : value;
    }) + '\n';
  }
};
