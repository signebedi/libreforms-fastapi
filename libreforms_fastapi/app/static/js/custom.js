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
    }, 15000);
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
      return `${user.relationship} <a href='/ui/auth/profile/${user.related_user_id}'>${user.related_user_username}</a>`;
  }).join(", ");
}



function prettifyTimeDiff(dateTimeStr, tz="America/New_York") {
  // console.log(dateTimeStr);

  // Parse the date string into a Date object
  // const date = new Date(dateTimeStr);
  const date = new Date(new Date(dateTimeStr).toLocaleString('en-US', { timeZone: tz }));
  // console.log(date);

  // Get the current date and time
  const now = new Date(new Date().toLocaleString('en-US', { timeZone: tz }));
  // const now = new Date();
  // console.log(now);

  // Calculate the difference in seconds
  const timeDiff = (now - date) / 1000; // convert milliseconds to seconds
  // const timeDiff = Math.abs((now - date) / 1000); // convert milliseconds to seconds
  // console.log(timeDiff);



  if (timeDiff < 3600) {
      if (timeDiff / 30 < 1) {
          return "seconds ago";
      } else if (timeDiff / 60 < 1) {
          return "less than a minute ago";
      } else if (timeDiff / 90 < 1) {
          return "about a minute ago";
      } else if (timeDiff / 420 < 1) {
          return "a few minutes ago";
      } else if (timeDiff / 900 < 1) {
          return "about 10 minutes ago";
      } else if (timeDiff / 1500 < 1) {
          return "about 20 minutes ago";
      } else if (timeDiff / 2100 < 1) {
          return "about 30 minutes ago";
      } else if (timeDiff / 2700 < 1) {
          return "about 30 minutes ago";
      } else if (timeDiff / 3300 < 1) {
          return "about 40 minutes ago";
      } else if (timeDiff / 3600 < 1) {
          return "about 50 minutes ago";
      }
  } else if (timeDiff >= 3600 && timeDiff < 7200) {
      return "about an hour ago";
  } else if (timeDiff >= 7200 && timeDiff < 84600) { // Shortened 86400 seconds by 1800 seconds to manage rounding issues
      return `about ${Math.round(timeDiff / 3600)} hours ago`;
  } else if (timeDiff >= 84600 && timeDiff <= 171000) { // Shortened 172800 seconds by 1800 seconds to manage rounding issues
      return "about a day ago";
  } else if (timeDiff > 171000) { // Shortened 172800 seconds by 1800 seconds to manage rounding issues
      return `about ${Math.round(timeDiff / 86400)} days ago`;
  } else {
      return "";
  }
}


function formatDate(
    dateString, 
    timeZone = 'America/New_York',
    locale = 'en-US',
    year = 'numeric',
    month = '2-digit',
    day = '2-digit',
    hour = '2-digit',
    minute = '2-digit',
    second = '2-digit'
) {
    // Convert string to Date object
    const date = new Date(dateString);
    const options = {
        year: year,
        month: month,
        day: day,
        hour: hour,
        minute: minute,
        second: second,
        timeZone: timeZone
    };

    const formatter = new Intl.DateTimeFormat(locale, options);
    return formatter.format(date);
}


function obfuscateString(input) {
    // Check if the string is 4 characters or less
    if (input.length <= 4) {
        // return '*'.repeat(input.length); // Obfuscate entire string with asterisks
        return '***************'; // Obfuscatestring and length with asterisks
    } else {
        // Replace all but the last 4 characters with asterisks
        // return '*'.repeat(input.length - 4) + input.slice(-4);
        return '************ ' + input.slice(-4); // Obfuscatestring and length with asterisks
        //return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-asterisk" viewBox="0 0 16 16"><path d="M8 0a1 1 0 0 1 1 1v5.268l4.562-2.634a1 1 0 1 1 1 1.732L10 8l4.562 2.634a1 1 0 1 1-1 1.732L9 9.732V15a1 1 0 1 1-2 0V9.732l-4.562 2.634a1 1 0 1 1-1-1.732L6 8 1.438 5.366a1 1 0 0 1 1-1.732L7 6.268V1a1 1 0 0 1 1-1"/></svg>'.repeat(15) + " " + input.slice(-4); // Obfuscate string and length with bootstrap icons


    }
}
