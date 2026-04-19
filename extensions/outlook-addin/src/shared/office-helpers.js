export async function getAttachments() {
  return new Promise((resolve, reject) => {
    Office.context.mailbox.item.getAttachmentsAsync((asyncResult) => {
      if (asyncResult.status === Office.AsyncResultStatus.Succeeded) {
        resolve(asyncResult.value);
      } else {
        reject(asyncResult.error);
      }
    });
  });
}

export async function getAttachmentContent(attachmentId) {
  return new Promise((resolve, reject) => {
    Office.context.mailbox.item.getAttachmentContentAsync(attachmentId, (asyncResult) => {
      if (asyncResult.status === Office.AsyncResultStatus.Succeeded) {
        resolve(asyncResult.value.content); // base64 string
      } else {
        reject(asyncResult.error);
      }
    });
  });
}

export async function removeAttachments(attachmentIds) {
  const item = Office.context.mailbox.item;
  for (const id of attachmentIds) {
    await new Promise((resolve, reject) => {
      item.removeAttachmentAsync(id, (asyncResult) => {
        if (asyncResult.status === Office.AsyncResultStatus.Succeeded) resolve();
        else reject(asyncResult.error);
      });
    });
  }
}

export async function insertIntoBody(html) {
  return new Promise((resolve, reject) => {
    Office.context.mailbox.item.body.prependAsync(
      html,
      { coercionType: Office.CoercionType.Html },
      (asyncResult) => {
        if (asyncResult.status === Office.AsyncResultStatus.Succeeded) resolve();
        else reject(asyncResult.error);
      }
    );
  });
}
