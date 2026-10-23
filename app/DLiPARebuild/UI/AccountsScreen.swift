import SwiftUI

struct AccountsScreen: View {
    var body: some View {
        NavigationView {
            EmptyStateView(
                title: "No Accounts",
                systemImage: "person.crop.circle",
                detail: "Add an Apple ID to sign in. Credentials stay on this device."
            )
            .navigationTitle("Accounts")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Image(systemName: "plus")
                        .foregroundColor(.accentColor)
                }
            }
        }
        .navigationViewStyle(.stack)
    }
}
