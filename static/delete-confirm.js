document.querySelectorAll(".delete-form").forEach(function(form) {
    form.addEventListener("submit", function(event) {
        const confirmed = confirm(
            "Are you sure you want to delete this message?"
        );

        if (!confirmed) {
            event.preventDefault();
        }
    });
});