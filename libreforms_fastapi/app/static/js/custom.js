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
