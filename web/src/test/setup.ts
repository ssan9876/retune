import "@testing-library/jest-dom/vitest";

// jsdom's Blob/File do not implement `.text()`, unlike every real browser, so
// tests that read an uploaded file's contents (e.g. a signature sidecar)
// need a polyfill.
if (typeof Blob !== "undefined" && !Blob.prototype.text) {
  Blob.prototype.text = function (this: Blob): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.onerror = () => reject(reader.error);
      reader.readAsText(this);
    });
  };
}
