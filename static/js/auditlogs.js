function toggleSection(sectionId) {
    console.log(`toggleSection called for: ${sectionId}`);

    // Hide all sections before toggling the desired one
    document.querySelectorAll('.admin-section').forEach(section => {
        console.log(`Hiding section: ${section.id}`);
        section.style.display = 'none';
    });

    const section = document.getElementById(sectionId);

    if (section) {
        section.style.display = 'block'; // Show the section
        console.log(`${sectionId} is now visible`);
    } else {
        console.error(`Section ${sectionId} not found.`);
        return; // Exit the function if the section is not found
    }

    // Call loadAuditLogs if the audit logs section is being toggled
    if (sectionId === 'auditLogsSection') {
        console.log("Calling loadAuditLogs...");
        loadAuditLogs();
    }
}

function loadAuditLogs(page = 1, perPage = 30) { // Set default perPage to 30
    console.log(`Starting to load audit logs (Page: ${page}, Per Page: ${perPage})...`);

    fetch(`/fetch_audit_logs?page=${page}&per_page=${perPage}`)
        .then(response => {
            console.log(`Fetch status: ${response.status}`);
            if (!response.ok) {
                throw new Error("Fetch failed");
            }
            return response.json();
        })
        .then(data => {
            console.log("Fetched data:", data);

            const tbody = document.querySelector('#auditLogsTable tbody');
            tbody.innerHTML = ''; // Clear old logs

            if (data.success) {
                console.log(`Rendering ${data.logs.length} logs...`);
                data.logs.forEach(log => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${log.user || 'System'}</td>
                        <td>${log.action}</td>
                        <td>${formatTargetFile(log.target_file)}</td>
                        <td>${log.timestamp ? new Date(log.timestamp).toLocaleString() : 'N/A'}</td>
                        <td>${formatExtraData(log.extra_data)}</td>
                    `;
                    tbody.appendChild(row);
                });

                // Update pagination controls
                updatePaginationControls(page, perPage, data.total);
            } else {
                console.error("Error from backend:", data.error);
            }
        })
        .catch(err => {
            console.error("Error loading logs:", err);
        });
}

function formatTargetFile(targetFile) {
    if (!targetFile || targetFile === 'N/A') {
        return 'No File Interacted';
    }
    try {
        // Use `split` to extract the filename from the path
        const fileName = targetFile.split(/[/\\]/).pop(); // Handles both '/' and '\' as path separators
        if (fileName.endsWith('.pdf')) {
            return fileName; // Return only the filename if it's a PDF
        }
        return 'No PDF File'; // If the file is not a PDF, indicate it
    } catch (error) {
        console.error("Error processing target file:", error);
        return 'Invalid File';
    }
}

function formatExtraData(extraData) {
    if (!extraData || extraData === "No Additional Information") {
        return "No Additional Information";
    }

    try {
        // Handle cases where extraData is a stringified JSON
        if (typeof extraData === "string") {
            extraData = JSON.parse(extraData); // Attempt to parse JSON string
        }

        // Format data dynamically based on its structure
        let formattedData = "";

        if (extraData.folder) {
            formattedData += `Folder: ${extraData.folder}<br>`;
        }
        if (extraData.department) {
            formattedData += `Department: ${extraData.department}<br>`;
        }
        if (extraData.filename) {
            formattedData += `Filename: ${extraData.filename}<br>`;
        }
        if (extraData.file_size) {
            formattedData += `File Size: ${extraData.file_size}<br>`;
        }
        if (extraData.user_id) {
            formattedData += `User ID: ${extraData.user_id}<br>`;
        }
        if (extraData.username) {
            formattedData += `Username: ${extraData.username}<br>`;
        }
        if (extraData.role_id !== undefined) {
            formattedData += `Role ID: ${extraData.role_id}<br>`;
        }
        if (extraData.department_ids) {
            formattedData += `Departments: ${extraData.department_ids.join(", ")}<br>`;
        }
        if (extraData.changes) {
            formattedData += `Changes:<br>`;
            for (const [key, change] of Object.entries(extraData.changes)) {
                formattedData += `- ${key}: ${change.old} → ${change.new}<br>`;
            }
        }

        // Return the formatted data or a fallback
        return formattedData || "No Additional Information";
    } catch (error) {
        console.error("Error formatting extra data:", error, extraData);
        return "Invalid Data"; // Fallback in case of unexpected errors
    }
}


console.log("Audit Logs Search and Filter Loaded");

// Search and Filter Functionality
document.addEventListener("DOMContentLoaded", function () {
    const searchInput = document.getElementById("searchUser");
    const filterRoleDropdown = document.getElementById("filterRole");
    const resetFiltersButton = document.getElementById("resetFilters"); // Reset button
    let searchQuery = ""; // Default search query
    let selectedRole = ""; // Default role filter

    // Event Listener for Search Input
    if (searchInput) {
        searchInput.addEventListener("input", function () {
            searchQuery = searchInput.value.trim().toLowerCase(); // Get search query
            console.log("Search Query Updated:", searchQuery);
            loadFilteredAuditLogs(1); // Reload filtered logs from page 1
        });
    } else {
        console.error("Search Input not found.");
    }

    // Event Listener for Role Filter Dropdown Change
    if (filterRoleDropdown) {
        filterRoleDropdown.addEventListener("change", function () {
            selectedRole = this.value; // Get selected role
            console.log("Selected Role Updated:", selectedRole);
            loadFilteredAuditLogs(1); // Reload filtered logs from page 1
        });
    } else {
        console.error("Role Filter Dropdown not found.");
    }

    // Event Listener for Reset Filters Button
    if (resetFiltersButton) {
        resetFiltersButton.addEventListener("click", function () {
            console.log("Resetting Filters...");

            // Clear search input and reset dropdown
            if (searchInput) searchInput.value = "";
            if (filterRoleDropdown) filterRoleDropdown.value = "";

            // Reset query variables
            searchQuery = "";
            selectedRole = "";

            // Reload logs without filters
            loadFilteredAuditLogs(1);
        });
    } else {
        console.error("Reset Filters Button not found.");
    }

    // Function to Load Filtered Audit Logs
    function loadFilteredAuditLogs(page = 1, perPage = 30) {
        console.log(`Loading Filtered Audit Logs (Page: ${page}, Per Page: ${perPage})...`);

        // Build query parameters for search and filter
        const queryParams = new URLSearchParams({
            page,
            per_page: perPage,
            search: searchQuery || "", // Default to empty string if no query
            role: selectedRole || "",  // Default to empty string for all roles
        });

        // Fetch logs with filters applied
        fetch(`/fetch_audit_logs?${queryParams.toString()}`)
            .then(response => {
                console.log(`Fetch Status: ${response.status}`);
                if (!response.ok) {
                    throw new Error("Fetch Failed");
                }
                return response.json();
            })
            .then(data => {
                console.log("Fetched Filtered Data:", data);

                const tbody = document.querySelector("#auditLogsTable tbody");
                tbody.innerHTML = ""; // Clear old logs

                if (data.success) {
                    console.log(`Rendering ${data.logs.length} filtered logs...`);
                    data.logs.forEach(log => {
                        const row = document.createElement("tr");
                        row.innerHTML = `
                            <td>${log.user || "System"}</td>
                            <td>${log.action}</td>
                            <td>${formatTargetFile(log.target_file)}</td>
                            <td>${log.timestamp ? new Date(log.timestamp).toLocaleString() : "N/A"}</td>
                            <td>${formatExtraData(log.extra_data)}</td>
                        `;
                        tbody.appendChild(row);
                    });

                    // Update Pagination Controls
                    updatePaginationControls(page, perPage, data.total);
                } else {
                    console.error("Error from Backend:", data.error);
                }
            })
            .catch(err => {
                console.error("Error Loading Filtered Logs:", err);
            });
    }

    // Initialize Filtered Logs on Page Load
    loadFilteredAuditLogs();
});


function updatePaginationControls(currentPage, perPage, totalItems) {
    const paginationControls = document.getElementById('paginationControls');
    if (!paginationControls) {
        console.error("Pagination controls element not found.");
        return;
    }

    paginationControls.innerHTML = ''; // Clear existing controls

    const totalPages = Math.ceil(totalItems / perPage);
    console.log(`Total Pages: ${totalPages}`);

    // Previous button
    const prevButton = document.createElement('button');
    prevButton.textContent = 'Previous';
    prevButton.disabled = currentPage === 1; // Disable on the first page
    prevButton.onclick = () => loadAuditLogs(currentPage - 1, perPage);
    paginationControls.appendChild(prevButton);

    // Page indicators
    const pageIndicator = document.createElement('span');
    pageIndicator.textContent = ` Page ${currentPage} of ${totalPages} `;
    paginationControls.appendChild(pageIndicator);

    // Next button
    const nextButton = document.createElement('button');
    nextButton.textContent = 'Next';
    nextButton.disabled = currentPage === totalPages; // Disable on the last page
    nextButton.onclick = () => loadAuditLogs(currentPage + 1, perPage);
    paginationControls.appendChild(nextButton);
}

document.addEventListener("DOMContentLoaded", function () {
    console.log("Page loaded, toggleSection is ready.");

    // Initial section setup (default to 'manageUsersSection' or another section)
    console.log("Toggling to default section: manageUsersSection");
    toggleSection('manageUsersSection');
});
