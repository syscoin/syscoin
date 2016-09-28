#ifndef MANAGEESCROWDIALOG_H
#define MANAGEESCROWDIALOG_H

#include <QDialog>
class WalletModel;
namespace Ui {
    class ManageEscrowDialog;
}

/** Dialog for editing an address and associated information.
 */
class ManageEscrowDialog : public QDialog
{
    Q_OBJECT

public:
    enum EscrowType {
        Buyer,
        Seller,
		Arbiter,
		None
    };
    explicit ManageEscrowDialog(WalletModel* model, const QString &escrow, QWidget *parent = 0);
    ~ManageEscrowDialog();

	bool isYourAlias(const QString &alias);
	bool loadEscrow(const QString &escrow, QString &buyer, QString &seller, QString &arbiter, QString &status, QString &offertitle, QString &total);
	ManageEscrowDialog::EscrowType findYourEscrowRoleFromAliases(const QString &buyer, const QString &seller, const QString &arbiter);
public Q_SLOTS:
	void on_releaseButton_clicked();
	void on_refundButton_clicked();
	void on_cancelButton_clicked();
private:
	void onLeaveFeedback();
	WalletModel* walletModel;
    Ui::ManageEscrowDialog *ui;
	QString escrow;
	QString refundWarningStr;
	QString releaseWarningStr;
};

#endif // MANAGEESCROWDIALOG_H
