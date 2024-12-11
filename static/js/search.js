document.addEventListener('DOMContentLoaded', function () {
    const searchForm = document.getElementById('search-form');
    const folderContainers = document.querySelectorAll('.folder-container');

    if (searchForm) {
        searchForm.addEventListener('submit', function (event) {
            event.preventDefault(); // Prevent form submission

            const query = document.getElementById('search-input').value.trim().toLowerCase();

            folderContainers.forEach(folder => {
                const folderName = folder.querySelector('.folder-name').textContent.toLowerCase();
                console.log('Folder Name:', folderName); // Log each folder name
            
                if (folderName.includes(query)) {
                    console.log('Match Found:', folderName);
                    folder.style.display = 'block';
                } else {
                    console.log('No Match:', folderName);
                    folder.style.display = 'none';
                }
            });
            
        });
    } else {
        console.error('Search form not found in the DOM.');
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
