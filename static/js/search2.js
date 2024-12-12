document.addEventListener("DOMContentLoaded", function () {
    const searchForm = document.getElementById("search-form");

    // Build folder map (include child and subchild info)
    const folderMap = {};
    document.querySelectorAll(".folder-container").forEach(folder => {
        const folderId = folder.dataset.folderid;
        const parentFolderId = folder.dataset.parentfolderid;
        folderMap[folderId] = { 
            element: folder, 
            parentFolderId: parentFolderId,
            children: [] // Track child folders
        };
    });

    // Populate children in the map
    document.querySelectorAll(".subfolder-container").forEach(container => {
        container.querySelectorAll(".subfolder-item").forEach(subfolder => {
            const parentFolderId = subfolder.closest('.folder-container').dataset.folderid;
            const subfolderId = subfolder.dataset.folderid;
            if (folderMap[parentFolderId]) {
                folderMap[parentFolderId].children.push(subfolderId);
            }
        });
    });

    if (searchForm) {
        searchForm.addEventListener("submit", function (event) {
            event.preventDefault(); // Prevent form submission

            const query = document.getElementById("search-input").value.trim().toLowerCase();
            console.log("Search Query:", query);

            // Track matching folders
            const matchingFolders = new Set();

            // Search folders
            Object.values(folderMap).forEach(({ element, parentFolderId, children }) => {
                const folderName = element.querySelector(".folder-name").textContent.toLowerCase();
                const isMatch = folderName.includes(query);

                // Add to matching folders
                if (isMatch) {
                    matchingFolders.add(element.dataset.folderid);
                }

                // Hide all folders initially
                element.style.display = "none";

                // Check child folders if this folder is a match
                children.forEach(childId => {
                    const child = folderMap[childId];
                    if (child) {
                        const childName = child.element.querySelector(".folder-name").textContent.toLowerCase();
                        if (childName.includes(query)) {
                            matchingFolders.add(childId);
                        }
                        // Hide child folder initially
                        child.element.style.display = "none";
                    }
                });
            });

            // Recursive display logic for matching folders and all their parents
            matchingFolders.forEach(folderId => showFolderAndParents(folderId, folderMap));
        });
    } else {
        console.error("Search form not found in the DOM.");
    }
});

// Show a folder and all its parents (including child and subchild)
function showFolderAndParents(folderId, folderMap) {
    const folder = folderMap[folderId];
    if (!folder) return;

    // Show this folder
    folder.element.style.display = "block";

    // Show its parent
    if (folder.parentFolderId) {
        showFolderAndParents(folder.parentFolderId, folderMap);
    }

    // Show child folders if they exist
    folder.children.forEach(childId => {
        const child = folderMap[childId];
        if (child) {
            child.element.style.display = "block";  // Show the child folder
            showFolderAndParents(childId, folderMap); // Also show its parent if necessary
        }
    });
}
