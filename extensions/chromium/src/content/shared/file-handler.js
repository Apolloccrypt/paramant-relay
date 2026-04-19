// file-handler.js — stub for Week 3+
// Will handle direct file reading from the page context,
// sandboxed FileReader progress, and chunking for large files.

// Currently not imported anywhere; gmail.js and outlook.js
// handle file reading inline. Extract here when complexity warrants it.

export function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}
