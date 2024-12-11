document.getElementById('search-form').addEventListener('submit', function (event) {
    event.preventDefault(); // Prevent default form submission

    const query = document.getElementById('search-input').value.trim().toLowerCase();
    const folderContainers = document.querySelectorAll('.folder-container');

    let matchFound = false;

    // Filter existing folders
    folderContainers.forEach(folder => {
        const folderName = folder.querySelector('.folder-name').textContent.toLowerCase();

        if (folderName.includes(query)) {
            folder.style.display = 'block'; // Show matching folders
            matchFound = true;
        } else {
            folder.style.display = 'none'; // Hide non-matching folders
        }
    });

    // Display a "No results" message if no matches are found
    const noResultsMessage = document.getElementById('no-results');
    if (!matchFound) {
        if (!noResultsMessage) {
            const message = document.createElement('p');
            message.id = 'no-results';
            message.textContent = 'No folders found matching your search criteria.';
            document.querySelector('.folder-container-wrapper').appendChild(message);
        }
    } else if (noResultsMessage) {
        noResultsMessage.remove(); // Remove message if matches are found
    }
});

document.querySelector('.reset-button').addEventListener('click', function (event) {
    event.preventDefault();

    const folderContainers = document.querySelectorAll('.folder-container');
    document.getElementById('search-input').value = ''; // Clear search input

    // Show all folders
    folderContainers.forEach(folder => {
        folder.style.display = 'block';
    });

    // Remove "No results" message if it exists
    const noResultsMessage = document.getElementById('no-results');
    if (noResultsMessage) {
        noResultsMessage.remove();
    }
});
