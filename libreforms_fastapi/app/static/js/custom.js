const AlertCategories = {
    SUCCESS: "success",
    DANGER: "danger",
    WARNING: "warning",
    INFO: "info"
};

function flashMessage(message, category) {
    // Check if the category is valid, default to 'info' if not
    if (!Object.values(AlertCategories).includes(category)) {
        console.error("Invalid category for flashMessage. Defaulting to 'info'.");
        category = AlertCategories.INFO;
    }

    // Proceed with creating and appending the alert message
    var alertDiv = $('<div></div>', {
        "class": "alert alert-dismissible alert-" + category,
        "role": "status"
    }).attr("aria-live", category === AlertCategories.INFO ? "polite" : "assertive");

    var dismissBtn = $('<button></button>', {
        "type": "button",
        "class": "btn-close",
        "data-bs-dismiss": "alert",
        "title": "dismiss-alert"
    });

    alertDiv.append(dismissBtn);
    alertDiv.append($("<strong>").text(message));
    $('.alerts-container').append(alertDiv);
    setTimeout(function() {
        alertDiv.fadeOut();
    }, 5000);
}


function setFlashMessage(message, category) {
    // Retrieve existing messages or start with an empty array if none exist
    const existingMessages = JSON.parse(localStorage.getItem('flashMessage') || '[]');
    // Add the new message
    existingMessages.push({ message, category });
    // Save the updated list of messages back to local storage
    localStorage.setItem('flashMessage', JSON.stringify(existingMessages));
}

function getAndClearFlashMessages() {
    const messages = JSON.parse(localStorage.getItem('flashMessage') || '[]');
    localStorage.removeItem('flashMessage'); // Clear all at once after reading
    return messages;
}

// These are a few functions for escaping content in the event the server side escaping
// proves insufficient.
function escapeHtml(text) {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

function escapeJsonData(data) {
  if (typeof data === 'string') {
    return escapeHtml(data);
  } else if (Array.isArray(data)) {
    return data.map(item => escapeJsonData(item));
  } else if (typeof data === 'object' && data !== null) {
    const escapedData = {};
    for (const [key, value] of Object.entries(data)) {
      escapedData[key] = escapeJsonData(value);
    }
    return escapedData;
  } else {
    // Return the data as-is if it's not a string, array, or object
    return data;
  }
}
  

function formatValue(value) {
  if (Array.isArray(value)) {
      // Format array as comma-separated string
      return value.join(', ');
  } else if (typeof value === 'object' && value !== null) {
      // Format object in a pretty way
      var formattedObject = '<ul>';
      for (var key in value) {
          formattedObject += `<li>${key}: ${formatValue(value[key])}</li>`; // Recursive call for nested objects
      }
      formattedObject += '</ul>';
      return formattedObject;
  } else {
      // Return other types (number, string) as is
      return value;
  }
}


function renderUserRelationships(users) {
  return users.map(user => {
      return `${user.relationship} <a href='/auth/profile/${user.related_user_id}'>${user.related_user_username}</a>`;
  }).join(", ");
}