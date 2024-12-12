document.addEventListener("DOMContentLoaded", function () {
    const searchForm = document.getElementById("search-form");

    // Build folder map
    const folderMap = {};
    document.querySelectorAll(".folder-container").forEach(folder => {
        const folderId = folder.dataset.folderid;
        const parentFolderId = folder.dataset.parentfolderid;
        folderMap[folderId] = { element: folder, parentFolderId: parentFolderId };
    });

    if (searchForm) {
        searchForm.addEventListener("submit", function (event) {
            event.preventDefault(); // Prevent form submission

            const query = document.getElementById("search-input").value.trim().toLowerCase();
            console.log("Search Query:", query);

            // Track matching folders
            const matchingFolders = new Set();

            // Search folders
            Object.values(folderMap).forEach(({ element, parentFolderId }) => {
                const folderName = element.querySelector(".folder-name").textContent.toLowerCase();
                const isMatch = folderName.includes(query);

                // Add to matching folders
                if (isMatch) {
                    matchingFolders.add(element.dataset.folderid);
                }

                // Explicitly hide all folders initially
                element.style.display = "none";
            });

            // Recursive display logic
            matchingFolders.forEach(folderId => showFolderAndParents(folderId, folderMap));
        });
    } else {
        console.error("Search form not found in the DOM.");
    }
});

// Show a folder and all its parents
function showFolderAndParents(folderId, folderMap) {
    const folder = folderMap[folderId];
    if (!folder) return;

    // Show this folder
    folder.element.style.display = "block";

    // Show its parent
    if (folder.parentFolderId) {
        showFolderAndParents(folder.parentFolderId, folderMap);
    }
}
