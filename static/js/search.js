document.addEventListener('DOMContentLoaded', function () {
    const searchInput = document.querySelector('input#search-input');
    const departments = document.querySelectorAll('.department-container');

    // Save original display states
    departments.forEach(department => {
        department.dataset.originalDisplay = department.style.display || '';
        const folderContainers = department.querySelectorAll('[data-folder-container]');
        folderContainers.forEach(folder => {
            folder.dataset.originalDisplay = folder.style.display || '';
        });
    });

    // Add event listener for search
    searchInput.addEventListener('input', function () {
        const query = searchInput.value.toLowerCase().trim();
        let anyDepartmentVisible = false; // Track if any department is visible

        // Process each department
        departments.forEach(department => {
            let departmentHasVisibleFolders = false; // Track if this department has visible folders

            const folderContainers = department.querySelectorAll('[data-folder-container]');

            // Process each folder in the department
            folderContainers.forEach(folder => {
                const folderName = folder.dataset.folderName.toLowerCase();
                if (query && folderName.includes(query)) {
                    folder.style.display = ''; // Show matching folder
                    departmentHasVisibleFolders = true; // Mark this department as having visible folders
                } else {
                    folder.style.display = 'none'; // Hide non-matching folder
                }
            });

            // Show or hide the department based on its folders' visibility
            if (departmentHasVisibleFolders) {
                department.style.display = ''; // Show department
                anyDepartmentVisible = true; // Mark that at least one department is visible
            } else {
                department.style.display = 'none'; // Hide department
            }
        });

        // If no departments are visible and query exists, hide everything
        if (!anyDepartmentVisible && query) {
            console.log('No matching results found for query:', query);
        }
    });
});
